"""Compare gVisor connect records with host packets, conntrack and delivery.

Two steps:

  reduce PRIVATE OUT   turn raw tcpdump/conntrack text (root-only, never
                       exported) into sanitized per-flow rows in OUT
  summarize OUT        join every level per case and write summary.json

Each case is classified at four levels, all for the workload's own Pod IP:
  syscall   connect enter/exit records with this container's claimed ID
  packets   packets from the Pod IP seen on the bridge (left the sandbox)
  conntrack host conntrack events whose original source is the Pod IP
  delivery  the host listener accepted (TCP) or received (UDP) from the Pod IP
"""
import argparse
import json
import pathlib
import re

CASES = {'tcp_established', 'tcp_refused', 'tcp_blackhole', 'tcp_policy_denied', 'udp_connect_only',
         'udp_sendto', 'udp_connect_send', 'dns_lookup', 'concurrent_a', 'concurrent_b', 'after_disconnect'}
ALLOWED = {'kind', 'message_type', 'connection', 'sender_cumulative_drops', 'source_time_ns', 'thread_id',
           'thread_group_id', 'context_container_id', 'container_id', 'phase', 'result', 'errno', 'fd',
           'destination', 'observed_ns'}
EINPROGRESS, ECONNREFUSED = 115, 111
# Blocking TCP connects that must appear in the trace for a run to count.
BASELINE = ('tcp_established', 'concurrent_a', 'concurrent_b')

# The capture filter admits only TCP, UDP and ICMP. A line without TCP flags is
# UDP; DNS lines are decoded by tcpdump and carry no "UDP," marker.
PACKET = re.compile(r'^(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): (?:Flags \[([^\]]*)\])?')
ICMP = re.compile(r'^(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): ICMP (.+?)(?:,|$)')
CT = re.compile(r'^\[(\d+\.\d+)\]\s+\[(NEW|UPDATE|DESTROY)\]\s+(tcp|udp)\s+\d+\s+(?:\d+\s+)?([A-Z_]+\s+)?'
                r'src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)')


TUPLE = re.compile(r'src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)')


def rows_json(rows):
    """One row per line keeps the evidence reviewable."""
    return '[\n' + ',\n'.join(json.dumps(r, sort_keys=True) for r in rows) + '\n]\n'


def reduce(private, out):
    """Keep only timestamp, 5-tuple, TCP flags and conntrack state, and only for
    the trial's own Pods. Other Pods on the node share the capture CIDR."""
    ips = {r['pod_ip'] for r in json.loads((out / 'runtime-ledger.json').read_text())}
    packets = []
    for name in ('bridge', 'uplink'):
        for line in (private / (name + '.txt')).read_text().splitlines():
            m = PACKET.match(line)
            if m:
                packets.append({'capture': name, 'ts_ns': int(float(m.group(1)) * 1e9), 'src': m.group(2),
                                'sport': int(m.group(3)), 'dst': m.group(4), 'dport': int(m.group(5)),
                                'proto': 'tcp' if m.group(6) is not None else 'udp', 'flags': m.group(6) or ''})
                continue
            m = ICMP.match(line)
            if m:
                # Keep only the ICMP type text tcpdump prints, never the quoted payload.
                kind = re.sub(r'[^a-z ]', '', m.group(4).split(' for ')[0].lower()).strip()[:40]
                packets.append({'capture': name, 'ts_ns': int(float(m.group(1)) * 1e9), 'src': m.group(2),
                                'sport': 0, 'dst': m.group(3), 'dport': 0, 'proto': 'icmp', 'flags': kind})
    flows = []
    for line in (private / 'conntrack.txt').read_text().splitlines():
        m = CT.match(line)
        if m:
            tuples = TUPLE.findall(line)
            reply = tuples[1] if len(tuples) > 1 else (None, None, 0, 0)
            flows.append({'ts_ns': int(float(m.group(1)) * 1e9), 'event': m.group(2), 'proto': m.group(3),
                          'state': (m.group(4) or '').strip(), 'src': m.group(5), 'dst': m.group(6),
                          'sport': int(m.group(7)), 'dport': int(m.group(8)),
                          'reply_src': reply[0], 'reply_dst': reply[1], 'reply_sport': int(reply[2]),
                          'reply_dport': int(reply[3]),
                          'replied': '[UNREPLIED]' not in line, 'assured': '[ASSURED]' in line})
    flows = [f for f in flows if f['src'] in ips]
    # After masquerading, an uplink packet carries the node address, not the Pod
    # IP. Keep it only if it is the NAT'd form of a trial flow, using the
    # conntrack reply tuple (in either direction).
    nat = set()
    for f in flows:
        if f['reply_src']:
            nat.add((f['reply_dst'], f['reply_dport'], f['reply_src'], f['reply_sport']))
            nat.add((f['reply_src'], f['reply_sport'], f['reply_dst'], f['reply_dport']))
    packets = [p for p in packets
               if (p['capture'] == 'bridge' and (p['src'] in ips or p['dst'] in ips))
               or (p['capture'] == 'uplink' and (p['src'], p['sport'], p['dst'], p['dport']) in nat)]
    (out / 'packets.json').write_text(rows_json(packets))
    (out / 'conntrack.json').write_text(rows_json(flows))


def connects(events, cid):
    rows = [e for e in events if e['kind'] == 'connect' and e.get('context_container_id') == cid]
    return [e for e in rows if e['phase'] == 'enter'], [e for e in rows if e['phase'] == 'exit']


def summarize(rows, events, packets, flows, delivery, counters, node):
    if {r['case'] for r in rows} != CASES:
        raise ValueError('incomplete case matrix')
    if counters['decode_or_transport_errors'] or counters['local_queue_drops'] or counters['rejected_connections']:
        raise ValueError('invalid research receiver accounting')
    # Missing records only mean something if the sender reported no drops.
    if any(e.get('sender_cumulative_drops', 0) for e in events):
        raise ValueError('runsc reported dropped trace events')
    if any(set(e) - ALLOWED for e in events):
        raise ValueError('unapproved retained event field')
    if any(r['exit_code'] != 0 for r in rows):
        raise ValueError('workload failed')
    # A missing connect record is evidence only if the trace was observed
    # working in the same run: every trial container's start claim arrived,
    # and the baseline blocking TCP connects were recorded at enter and exit.
    if not events:
        raise ValueError('empty trace')
    claimed = {e.get('container_id') for e in events if e['kind'] == 'container_start_claim'}
    if any(r['container_id'] not in claimed for r in rows):
        raise ValueError('trace missed a trial container start')
    for r in rows:
        if r['case'] in BASELINE:
            enters, exits = connects(events, r['container_id'])
            if len(enters) != 1 or [(e.get('errno'), e.get('destination')) for e in exits] != \
                    [(0, {'family': 'inet', 'port': 18080, 'address': node})]:
                raise ValueError('baseline connect evidence missing for ' + r['case'])
    findings = []
    for r in rows:
        cid, ip = r['container_id'], r['pod_ip']
        enters, exits = connects(events, cid)
        inet = [e for e in exits if e.get('destination', {}).get('family') == 'inet']
        sends = [e for e in events if e['kind'] in ('sendto', 'sendmsg') and e.get('context_container_id') == cid
                 and e.get('phase') == 'exit']
        out_packets = [p for p in packets if p['capture'] == 'bridge' and p['src'] == ip]
        syn = [p for p in out_packets if p['proto'] == 'tcp' and p['flags'] == 'S']
        replies = [p for p in packets if p['capture'] == 'bridge' and p['dst'] == ip]
        icmp = sorted({p['flags'] for p in replies if p['proto'] == 'icmp'})
        ct = [f for f in flows if f['src'] == ip]
        delivered = [d for d in delivery if d['peer'] == ip]
        findings.append({
            'case': r['case'],
            'connect_enter': len(enters),
            'connect_exit': [{'destination': e.get('destination'), 'result': e.get('result'), 'errno': e.get('errno')}
                             for e in inet],
            'send_syscalls': len(sends),
            'packets_from_pod': len(out_packets),
            'tcp_syn_from_pod': len(syn),
            'packets_to_pod': len(replies),
            'packet_destinations': sorted({'%s:%d/%s' % (p['dst'], p['dport'], p['proto']) for p in out_packets}),
            'icmp_to_pod': icmp,
            # Only the blackhole case sends to TEST-NET-1, so every uplink packet is its own (after NAT).
            'uplink_packets_to_blackhole': sum(1 for p in packets if p['capture'] == 'uplink' and p['proto'] == 'tcp')
                                           if r['case'] == 'tcp_blackhole' else None,
            'conntrack_events': sorted({'%s %s %s%s' % (f['event'], f['proto'], f['state'],
                                                        ' assured' if f['assured'] else '') for f in ct}),
            'conntrack_destinations': sorted({'%s:%d/%s' % (f['dst'], f['dport'], f['proto']) for f in ct}),
            'delivered': [{'proto': d['proto'], 'bytes': d['bytes']} for d in delivered],
            'receiver_disconnected': r.get('running_at_disconnect') is True and 'receiver_disconnected_ns' in r,
        })
    by_case = {f['case']: f for f in findings}
    if not by_case['after_disconnect']['receiver_disconnected']:
        raise ValueError('disconnect case did not disconnect a running workload')
    return {
        'node': node,
        'cases': findings,
        'connect_record_without_packets': [c for c in ('udp_connect_only',) if by_case[c]['connect_exit']
                                           and not by_case[c]['packets_from_pod']],
        'packets_without_connect_record': [c for c, f in by_case.items() if f['packets_from_pod']
                                           and not f['connect_exit']],
        'production_network_events_emitted': 0,
    }


def load(root):
    read = lambda name: json.loads((root / name).read_text())
    return (read('runtime-ledger.json'), read('events.json'), read('packets.json'), read('conntrack.json'),
            read('delivery.json'), read('receiver.json'))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command', required=True)
    r = sub.add_parser('reduce')
    r.add_argument('private')
    r.add_argument('output')
    s = sub.add_parser('summarize')
    s.add_argument('output')
    s.add_argument('--node-ip', required=True)
    args = p.parse_args()
    if args.command == 'reduce':
        reduce(pathlib.Path(args.private), pathlib.Path(args.output))
        return
    root = pathlib.Path(args.output)
    summary = summarize(*load(root), node=args.node_ip)
    (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
