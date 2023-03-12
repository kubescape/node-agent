package conthandler

import "testing"

func TestIsWLIDInExpectedFormat(t *testing.T) {
	wlid := "wlid://cluster-blabla/namespace-blublu/deployment-aaa"

	if !isWLIDInExpectedFormat(wlid) {
		t.Fatalf("wlid %s is not in the expected format", wlid)
	}

	wlid = "cluster-/namespace-blublu/deployment-aaa"
	if isWLIDInExpectedFormat(wlid) {
		t.Fatalf("wlid %s is in the expected format", wlid)
	}

	wlid = "wlid://cluster-/namespace-blublu/deployment-aaa"
	if isWLIDInExpectedFormat(wlid) {
		t.Fatalf("wlid %s is in the expected format", wlid)
	}

	wlid = "wlid://cluster-blabla/namspace-blublu/deployment-aaa"
	if isWLIDInExpectedFormat(wlid) {
		t.Fatalf("wlid %s is in the expected format", wlid)
	}

	wlid = "wlid://cluster-blabla/namespace-/deployment-aaa"
	if isWLIDInExpectedFormat(wlid) {
		t.Fatalf("wlid %s is in the expected format", wlid)
	}

	wlid = "wlid://cluster-blabla/namespace-/deployment"
	if isWLIDInExpectedFormat(wlid) {
		t.Fatalf("wlid %s is in the expected format", wlid)
	}
}
