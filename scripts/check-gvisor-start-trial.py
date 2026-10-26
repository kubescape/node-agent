#!/usr/bin/env python3
"""Check sanitized probe records against independently recorded runtime starts.

This does not authenticate the runtime manifest or prove any live-trial gate.
Never include input records, IDs, canaries, or parser errors in diagnostics.
"""
import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 16 * 1024 * 1024
FIELDS = {"Source", "ContainerID", "ObservedAt", "Dropped"}


class InvalidEvidence(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidEvidence("duplicate JSON field")
        result[key] = value
    return result


def load_json(data):
    return json.loads(data, object_pairs_hook=unique_object)


def read_artifact(path, canary):
    with Path(path).open("rb") as artifact:
        data = artifact.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise InvalidEvidence("artifact exceeds checker size limit")
    if canary.encode() in data:
        raise InvalidEvidence("privacy canary found in retained artifact")
    return data


def check(expected_path, events_path, canary, artifacts=()):
    if re.fullmatch(r"[A-Za-z0-9_-]{16,}", canary) is None:
        raise InvalidEvidence("use a synthetic canary of at least 16 ASCII letters, digits, underscores or hyphens")
    expected = load_json(read_artifact(expected_path, canary))
    if not isinstance(expected, dict) or not expected:
        raise InvalidEvidence("expected starts must be a nonempty ID-to-count object")
    if any(not key or type(count) is not int or count < 1
           for key, count in expected.items()):
        raise InvalidEvidence("expected start counts must be positive integers")
    if canary in json.dumps(expected):
        raise InvalidEvidence("privacy canary found in decoded manifest")
    observed = Counter()
    for line in read_artifact(events_path, canary).splitlines():
        if not line.strip():
            raise InvalidEvidence("blank JSONL record")
        event = load_json(line)
        if not isinstance(event, dict) or set(event) != FIELDS:
            raise InvalidEvidence("start record has missing or unexpected fields")
        if canary in json.dumps(event):
            raise InvalidEvidence("privacy canary found in decoded start record")
        if event["Source"] != "gvisor_trace":
            raise InvalidEvidence("unexpected event source")
        if not isinstance(event["ContainerID"], str) or event["ContainerID"] not in expected:
            raise InvalidEvidence("start record has an unexpected identity")
        if type(event["Dropped"]) is not int or event["Dropped"] != 0:
            raise InvalidEvidence("start record reports invalid or nonzero sender drops")
        if not isinstance(event["ObservedAt"], str):
            raise InvalidEvidence("invalid observation timestamp")
        match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,9})?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", event["ObservedAt"])
        if match is None:
            raise InvalidEvidence("observation timestamp must be RFC3339 with a timezone")
        # Python 3.9 accepts microseconds; Go emits up to nine fractional digits.
        fraction = (match[2] or "")[:7]
        datetime.fromisoformat(match[1] + fraction + match[3].replace("Z", "+00:00"))
        observed[event["ContainerID"]] += 1
    for artifact in artifacts:
        read_artifact(artifact, canary)
    if observed != Counter(expected):
        raise InvalidEvidence("observed start counts do not match runtime manifest")
    return sum(observed.values())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True, help="runtime-derived JSON ID-to-count manifest")
    parser.add_argument("--events", required=True, help="probe JSONL stdout")
    parser.add_argument("--canary", required=True, help="synthetic marker matching [A-Za-z0-9_-]{16,}, never a real secret")
    parser.add_argument("--artifact", action="append", default=[], help="additional retained file to scan for the canary; repeatable")
    args = parser.parse_args(argv)
    try:
        count = check(args.expected, args.events, args.canary, args.artifact)
    except InvalidEvidence as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        print("FAIL: unreadable or malformed evidence (input omitted)", file=sys.stderr)
        return 1
    print(f"PASS: {count} retained start records match expected counts with zero reported sender drops.")
    print("Live runtime provenance, concurrency, timing, local queue loss, and deployment gates still require review.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
