#pragma once

#define NETWORK_PATH_MAX 512

#define PACKET_HOST 0
#define PACKET_OUTGOING 4

struct event_t {
	gadget_timestamp timestamp_raw;
	gadget_netns_id netns_id;
	struct gadget_l4endpoint_t endpoint;
	struct gadget_process proc;
	__u8 egress;
	char exepath[NETWORK_PATH_MAX];
};
