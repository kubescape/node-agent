package containerprofilemanager

// Raw observations may acquire selectors and additional Service ports only at
// flush time. Apply the size budget to their materialized profile, which also
// freezes those ports across any subsequent queue splits.
func hasUnresolvedNetworkPeers(data *containerData) bool {
	if data.networks == nil {
		return false
	}
	for _, event := range data.networks.ToSlice() {
		if event.Destination.Kind != EndpointKindPod && event.Destination.Kind != EndpointKindService {
			return true
		}
	}
	return false
}
