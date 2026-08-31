package dnsmanager

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"math/rand/v2"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"

	mapset "github.com/deckarep/golang-set/v2"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestResolveIPAddress(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		dnsEvent    *utils.StructEvent
		ipAddr      string
		want        string
		wantOk      bool
	}{
		{
			name:        "ip found with container id",
			containerID: "container-123",
			ipAddr:      "67.225.146.248",
			dnsEvent: &utils.StructEvent{
				EventType:   utils.DnsEventType,
				ContainerID: "container-123",
				DNSName:     "test.com",
				Addresses: []string{
					"67.225.146.248",
				},
			},
			want:   "test.com",
			wantOk: true,
		},
		{
			name:        "ip not found",
			containerID: "container-123",
			ipAddr:      "67.225.146.248",
			dnsEvent: &utils.StructEvent{
				EventType:   utils.DnsEventType,
				ContainerID: "container-123",
				DNSName:     "test.com",
				Addresses: []string{
					"54.23.332.4",
				},
			},
			want:   "",
			wantOk: false,
		},
		{
			name:        "no address",
			containerID: "container-123",
			ipAddr:      "67.225.146.248",
			dnsEvent: &utils.StructEvent{
				EventType:   utils.DnsEventType,
				ContainerID: "container-123",
				DNSName:     "test.com",
			},
			want:   "",
			wantOk: false,
		},
		{
			name:        "host process with empty container id",
			containerID: "",
			ipAddr:      "1.1.1.1",
			dnsEvent: &utils.StructEvent{
				EventType:   utils.DnsEventType,
				ContainerID: "",
				DNSName:     "one.one.one.one",
				Addresses: []string{
					"1.1.1.1",
				},
			},
			want:   "one.one.one.one",
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := CreateDNSManager(1000)

			dm.ReportEvent(tt.dnsEvent)
			got, ok := dm.ResolveIPAddress(tt.containerID, tt.ipAddr)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantOk, ok)
		})
	}
}

func TestResolveIPAddressFallback(t *testing.T) {
	// Skip the test if running in CI or without network access
	if testing.Short() {
		t.Skip("Skipping test that requires network access")
	}

	tests := []struct {
		name     string
		dnsEvent *utils.StructEvent
		want     string
		wantOk   bool
	}{
		{
			name: "dns resolution fallback",
			dnsEvent: &utils.StructEvent{
				EventType:   utils.DnsEventType,
				ContainerID: "test-container-fallback",
				DNSName:     "example.com", // Using example.com as it's guaranteed to exist
			},
			want:   "example.com",
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := CreateDNSManager(1000)

			// Perform the actual DNS lookup
			addresses, err := net.LookupIP(tt.dnsEvent.DNSName)
			if err != nil {
				t.Skipf("DNS lookup failed: %v", err)
				return
			}
			if len(addresses) == 0 {
				t.Skip("No addresses returned from DNS lookup")
				return
			}

			dm.ReportEvent(tt.dnsEvent)
			got, ok := dm.ResolveIPAddress(tt.dnsEvent.ContainerID, addresses[0].String())
			if got != tt.want || ok != tt.wantOk {
				t.Errorf("ResolveIPAddress() got = %v, ok = %v, want = %v, wantOk = %v", got, ok, tt.want, tt.wantOk)
			}
		})
	}
}

func TestContainerDNSIsolation(t *testing.T) {
	dm := CreateDNSManager(1000)

	container1 := "workload-ai-client-123"
	container2 := "workload-kube-proxy-456"
	sharedCDNIP := "104.18.7.192"

	// Container 1 queries an AI provider sitting behind a shared CDN IP
	dm.ReportEvent(&utils.StructEvent{
		EventType:   utils.DnsEventType,
		ContainerID: container1,
		DNSName:     "api.openai.com",
		Addresses:   []string{sharedCDNIP},
	})

	// Container 2 queries an internal/unrelated service
	dm.ReportEvent(&utils.StructEvent{
		EventType:   utils.DnsEventType,
		ContainerID: container2,
		DNSName:     "internal-service.local",
		Addresses:   []string{"10.0.0.50"},
	})

	// Verify Container 1 resolves the IP to api.openai.com
	domain1, ok1 := dm.ResolveIPAddress(container1, sharedCDNIP)
	assert.True(t, ok1)
	assert.Equal(t, "api.openai.com", domain1)

	// Verify Container 2 does NOT inherit api.openai.com when connecting to the same IP
	domain2, ok2 := dm.ResolveIPAddress(container2, sharedCDNIP)
	assert.False(t, ok2)
	assert.Equal(t, "", domain2)

	// Verify Container 2 resolves its own queried domain
	domain2Internal, ok2Internal := dm.ResolveIPAddress(container2, "10.0.0.50")
	assert.True(t, ok2Internal)
	assert.Equal(t, "internal-service.local", domain2Internal)

	// Verify Container 1 does NOT resolve Container 2's domain
	domain1Internal, ok1Internal := dm.ResolveIPAddress(container1, "10.0.0.50")
	assert.False(t, ok1Internal)
	assert.Equal(t, "", domain1Internal)

	// Host queries a host service
	dm.ReportEvent(&utils.StructEvent{
		EventType:   utils.DnsEventType,
		ContainerID: armotypes.HostContainerID,
		DNSName:     "host-service.internal",
		Addresses:   []string{"192.168.1.10"},
	})

	// Verify both "host" and "" resolve host traffic
	domainHost, okHost := dm.ResolveIPAddress(armotypes.HostContainerID, "192.168.1.10")
	assert.True(t, okHost)
	assert.Equal(t, "host-service.internal", domainHost)

	domainEmpty, okEmpty := dm.ResolveIPAddress("", "192.168.1.10")
	assert.True(t, okEmpty)
	assert.Equal(t, "host-service.internal", domainEmpty)

	// Verify regular containers do NOT resolve host queries
	domainContainer1Host, okContainer1Host := dm.ResolveIPAddress(container1, "192.168.1.10")
	assert.False(t, okContainer1Host)
	assert.Equal(t, "", domainContainer1Host)
}

func TestContainerDNSLifecycleCleanup(t *testing.T) {
	dm := CreateDNSManager(1000)

	containerID := "short-lived-pod-789"
	ip := "93.184.216.34"

	// Add container
	dm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
					ContainerID: containerID,
				},
			},
		},
	})

	// Report DNS event
	dm.ReportEvent(&utils.StructEvent{
		EventType:   utils.DnsEventType,
		ContainerID: containerID,
		DNSName:     "example.org",
		Addresses:   []string{ip},
	})

	// Verify resolution works before removal
	domain, ok := dm.ResolveIPAddress(containerID, ip)
	assert.True(t, ok)
	assert.Equal(t, "example.org", domain)

	// Remove container
	dm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeRemoveContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
					ContainerID: containerID,
				},
			},
		},
	})

	// Verify existing resolutions remain readable during removal grace period for terminal profile save
	domainDuringGrace, okDuringGrace := dm.ResolveIPAddress(containerID, ip)
	assert.True(t, okDuringGrace)
	assert.Equal(t, "example.org", domainDuringGrace)

	// In-flight DNS event arrives after container removal
	dm.ReportEvent(&utils.StructEvent{
		EventType:   utils.DnsEventType,
		ContainerID: containerID,
		DNSName:     "late-arrival.org",
		Addresses:   []string{"1.2.3.4"},
	})

	// Verify no cache was resurrected or updated for late-arriving event
	domainLate, okLate := dm.ResolveIPAddress(containerID, "1.2.3.4")
	assert.False(t, okLate)
	assert.Equal(t, "", domainLate)

	// Explicitly simulate grace period expiration
	dm.cacheMu.Lock()
	dm.containerToAddressToDomain.Remove(containerID)
	dm.cacheMu.Unlock()

	domainAfterGrace, okAfterGrace := dm.ResolveIPAddress(containerID, ip)
	assert.False(t, okAfterGrace)
	assert.Equal(t, "", domainAfterGrace)
}

func TestCacheFallbackBehavior(t *testing.T) {
	dm := CreateDNSManager(1000)

	// Test successful DNS lookup caching
	event := &utils.StructEvent{
		EventType: utils.DnsEventType,
		DNSName:   "test.com",
		Addresses: []string{
			"1.2.3.4",
		},
	}
	dm.ReportEvent(event)

	// Check if the lookup is cached
	cached, found := dm.lookupCache.Get(event.DNSName)
	if !found {
		t.Error("Expected DNS lookup to be cached")
	}

	entry, ok := cached.(cacheEntry)
	if !ok {
		t.Error("Cached entry is not of type cacheEntry")
	}
	if len(entry.addresses) != 1 || entry.addresses[0] != "1.2.3.4" {
		t.Error("Cached addresses do not match expected values")
	}

	// Test failed lookup caching
	failEvent := &utils.StructEvent{
		EventType: utils.DnsEventType,
		DNSName:   "nonexistent.local",
	}
	dm.ReportEvent(failEvent)

	// Check if the failure is cached
	_, found = dm.failureCache.Get(failEvent.DNSName)
	if !found {
		t.Error("Expected failed DNS lookup to be cached")
	}

	// Test cache hit behavior
	hitCount := 0
	for i := 0; i < 5; i++ {
		if cached, found := dm.lookupCache.Get(event.DNSName); found {
			entry := cached.(cacheEntry)
			if len(entry.addresses) > 0 {
				hitCount++
			}
		}
	}
	if hitCount != 5 {
		t.Errorf("Expected 5 cache hits, got %d", hitCount)
	}
}

func TestConcurrentAccess(t *testing.T) {
	dm := CreateDNSManager(1000)
	const numGoroutines = 100
	const numOperations = 1000

	// Create a wait group to synchronize goroutines
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Create some test data
	testEvents := []*utils.StructEvent{
		{
			EventType: utils.DnsEventType,
			DNSName:   "test1.com",
			Addresses: []string{"1.1.1.1", "2.2.2.2"},
		},
		{
			EventType: utils.DnsEventType,
			DNSName:   "test2.com",
			Addresses: []string{"3.3.3.3", "4.4.4.4"},
		},
		{
			EventType: utils.DnsEventType,
			DNSName:   "test3.com",
			Addresses: []string{"5.5.5.5", "6.6.6.6"},
		},
	}

	// Launch multiple goroutines to concurrently access the cache
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				// Randomly choose between writing and reading
				if rand.Float32() < 0.5 {
					// Write operation
					event := testEvents[rand.IntN(len(testEvents))]
					dm.ReportEvent(event)
				} else {
					// Read operation
					if cached, found := dm.lookupCache.Get("test1.com"); found {
						entry := cached.(cacheEntry)
						// Verify the slice hasn't been modified
						if len(entry.addresses) != 2 {
							t.Errorf("Unexpected number of addresses: %d", len(entry.addresses))
						}
					}
				}
			}
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify final state
	for _, event := range testEvents {
		if cached, found := dm.lookupCache.Get(event.DNSName); found {
			entry := cached.(cacheEntry)
			if len(entry.addresses) != len(event.Addresses) {
				t.Errorf("Cache entry for %s has wrong number of addresses: got %d, want %d",
					event.DNSName, len(entry.addresses), len(event.Addresses))
			}
		}
	}
}

func TestIsCloudService(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		// AWS tests
		{"AWS EC2", "ec2.amazonaws.com.", true},
		{"AWS S3", "mybucket.s3.amazonaws.com.", true},
		{"AWS CloudFront", "d1234.cloudfront.net.", true},
		{"AWS Console", "console.aws.amazon.com.", true},
		{"AWS Elastic Beanstalk", "myapp.elasticbeanstalk.com.", true},

		// Azure tests
		{"Azure Web App", "myapp.azurewebsites.net.", true},
		{"Azure Cloud App", "myservice.cloudapp.net.", true},
		{"Azure API", "api.azure-api.net.", true},
		{"Azure Portal", "portal.azure.com.", true},

		// GCP tests
		{"Google APIs", "storage.googleapis.com.", true},
		{"App Engine", "myapp.appspot.com.", true},
		{"Cloud Functions", "function.cloudfunctions.net.", true},
		{"Cloud Run", "myservice.run.app.", true},

		// Negative tests
		{"Regular Domain", "example.com.", false},
		{"Subdomain", "sub.example.com.", false},
		{"Empty String", "", false},
		{"Single Dot", ".", false},
		{"Similar But Not Cloud", "notamazonsaws.com.", false},
		// {"Non Cloud With Azure In Name", "fake-azure.com.", false}, // Because of cpu usage we keep the check "simple".

		// Edge cases
		{"Domain Without Final Dot", "example.amazonaws.com", false},
		{"Multiple Dots", "my.app.amazonaws.com.", true},
		{"Uppercase Domain", "MYAPP.AMAZONAWS.COM.", true},
		{"Mixed Case Domain", "MyApp.AmAzOnAwS.cOm.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCloudService(strings.ToLower(tt.domain)) // Convert input to lowercase
			if result != tt.expected {
				t.Errorf("isCloudService(%q) = %v; want %v",
					tt.domain, result, tt.expected)
			}
		})
	}
}

// Benchmark function remains the same
func BenchmarkIsCloudService(b *testing.B) {
	testDomains := []string{
		"ec2.amazonaws.com.",
		"example.com.",
		"myapp.azurewebsites.net.",
		"storage.googleapis.com.",
		"notacloud.com.",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, domain := range testDomains {
			isCloudService(domain)
		}
	}
}

func TestContainerCloudServices(t *testing.T) {
	t.Run("full container lifecycle with cloud services", func(t *testing.T) {
		// SETUP
		dm := CreateDNSManager(1000)
		containerId := "test-container-123"
		testPid := uint32(1234)

		// Add container
		dm.ContainerCallback(containercollection.PubSubEvent{
			Type: containercollection.EventTypeAddContainer,
			Container: &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
						ContainerID: containerId,
					},
				},
			},
		})

		// Verify container was added properly
		pidToServices, found := dm.containerToCloudServices.Load(containerId)
		if !found {
			t.Fatal("Container was not added to containerToCloudServices map")
		}

		// Create new set for the PID
		services := mapset.NewSet[string]()
		pidToServices.Set(testPid, services)

		// Process cloud service DNS events
		cloudEvents := []*utils.StructEvent{
			{
				EventType:   utils.DnsEventType,
				ContainerID: containerId,
				DNSName:     "test.amazonaws.com.",
				Pid:         testPid,
			},
			{
				EventType:   utils.DnsEventType,
				ContainerID: containerId,
				DNSName:     "example.azure.com.",
				Pid:         testPid,
			},
		}

		// Process each event
		for _, event := range cloudEvents {
			t.Logf("Processing event for DNS: %s", event.DNSName)
			dm.ReportEvent(event)
		}

		// Verify services were added
		resultServices := dm.ResolveContainerProcessToCloudServices(containerId, testPid)
		if resultServices == nil {
			t.Fatal("Expected non-nil service set")
		}

		expectedServices := mapset.NewSet[string]("test.amazonaws.com.", "example.azure.com.")
		if !resultServices.Equal(expectedServices) {
			t.Errorf("Expected services %v, got %v", expectedServices, resultServices)
		}

		// Test container removal
		dm.ContainerCallback(containercollection.PubSubEvent{
			Type: containercollection.EventTypeRemoveContainer,
			Container: &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
						ContainerID: containerId,
					},
				},
			},
		})

		// Verify services are removed
		resultServices = dm.ResolveContainerProcessToCloudServices(containerId, testPid)
		if resultServices != nil {
			t.Error("Expected nil services after container removal")
		}
	})

	t.Run("max service cache size", func(t *testing.T) {
		dm := CreateDNSManager(1000)
		containerId := "test-container-456"
		testPid := uint32(5678)

		// Add container
		dm.ContainerCallback(containercollection.PubSubEvent{
			Type: containercollection.EventTypeAddContainer,
			Container: &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
						ContainerID: containerId,
					},
				},
			},
		})

		// Initialize the services set for the PID
		if pidToServices, found := dm.containerToCloudServices.Load(containerId); found {
			services := mapset.NewSet[string]()
			pidToServices.Set(testPid, services)
		}

		// Add more services than the cache size
		for i := 0; i <= maxServiceCacheSize+5; i++ {
			event := &utils.StructEvent{
				ContainerID: containerId,
				DNSName:     fmt.Sprintf("service%d.amazonaws.com.", i),
				Pid:         testPid,
			}
			dm.ReportEvent(event)
		}

		// Verify cache size limit is enforced
		services := dm.ResolveContainerProcessToCloudServices(containerId, testPid)
		if services == nil {
			t.Fatal("Expected non-nil service set")
		}
		if services.Cardinality() > maxServiceCacheSize {
			t.Errorf("Expected service set size to be <= %d, got %d",
				maxServiceCacheSize, services.Cardinality())
		}
	})
}

func TestCloudServiceCacheLimit(t *testing.T) {
	dm := CreateDNSManager(1000)
	containerId := "test-container-456"
	testPid := uint32(5678)

	// Add container
	dm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
					ContainerID: containerId,
				},
			},
		},
	})

	// Add more than maxServiceCacheSize cloud services
	for i := 0; i < maxServiceCacheSize+10; i++ {
		dm.ReportEvent(&utils.StructEvent{
			EventType:   utils.DnsEventType,
			ContainerID: containerId,
			DNSName:     fmt.Sprintf("service%d.amazonaws.com.", i),
			Pid:         testPid,
		})
	}

	// Give some time for events to be processed
	time.Sleep(100 * time.Millisecond)

	services := dm.ResolveContainerProcessToCloudServices(containerId, testPid)
	if services == nil {
		// Debug information
		t.Log("Debug: Checking container existence")
		if pidToServices, found := dm.containerToCloudServices.Load(containerId); found {
			t.Log("Container found in map")
			if services, found := pidToServices.Load(testPid); found {
				t.Log("PID found in map")
				t.Logf("Services: %v", services)
			} else {
				t.Log("PID not found in map")
			}
		} else {
			t.Log("Container not found in map")
		}
		t.Fatal("Expected non-nil service set")
	}

	if services.Cardinality() > maxServiceCacheSize {
		t.Errorf("Service cache exceeded maximum size: got %d, want <= %d",
			services.Cardinality(), maxServiceCacheSize)
	}
}

func TestCreateDNSManager_NonPositiveSize(t *testing.T) {
	for _, size := range []int{0, -1, -100} {
		dm := CreateDNSManager(size)
		assert.NotNil(t, dm, "CreateDNSManager(%d) must not return nil", size)
		assert.Equal(t, defaultDNSCacheSize, dm.cacheSize)
		assert.Equal(t, defaultPerContainerCacheSize, dm.perContainerCacheSize)
		assert.NotNil(t, dm.hostAddressToDomain)
	}
}
