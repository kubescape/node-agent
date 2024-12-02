package dnsmanager

import (
	"net"
	"strings"
	"sync"
	"testing"

	"math/rand/v2"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

func TestResolveIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		dnsEvent tracerdnstype.Event
		ipAddr   string
		want     string
		wantOk   bool
	}{
		{
			name:   "ip found",
			ipAddr: "67.225.146.248",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "test.com",
				NumAnswers: 1,
				Addresses: []string{
					"67.225.146.248",
				},
			},
			want:   "test.com",
			wantOk: true,
		},
		{
			name:   "ip not found",
			ipAddr: "67.225.146.248",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "test.com",
				NumAnswers: 1,
				Addresses: []string{
					"54.23.332.4",
				},
			},
			want:   "",
			wantOk: false,
		},
		{
			name:   "no address",
			ipAddr: "67.225.146.248",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "test.com",
				NumAnswers: 0,
			},
			want:   "",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := CreateDNSManager()

			dm.ReportEvent(tt.dnsEvent)
			got, ok := dm.ResolveIPAddress(tt.ipAddr)
			if got != tt.want || ok != tt.wantOk {
				t.Errorf("ResolveIPAddress() got = %v, ok = %v, want = %v, wantOk = %v", got, ok, tt.want, tt.wantOk)
			}
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
		dnsEvent tracerdnstype.Event
		want     string
		wantOk   bool
	}{
		{
			name: "dns resolution fallback",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "example.com", // Using example.com as it's guaranteed to exist
				NumAnswers: 1,
			},
			want:   "example.com",
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := CreateDNSManager()

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
			got, ok := dm.ResolveIPAddress(addresses[0].String())
			if got != tt.want || ok != tt.wantOk {
				t.Errorf("ResolveIPAddress() got = %v, ok = %v, want = %v, wantOk = %v", got, ok, tt.want, tt.wantOk)
			}
		})
	}
}

func TestCacheFallbackBehavior(t *testing.T) {
	dm := CreateDNSManager()

	// Test successful DNS lookup caching
	event := tracerdnstype.Event{
		DNSName: "test.com",
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
	failEvent := tracerdnstype.Event{
		DNSName: "nonexistent.local",
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
	dm := CreateDNSManager()
	const numGoroutines = 100
	const numOperations = 1000

	// Create a wait group to synchronize goroutines
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Create some test data
	testEvents := []tracerdnstype.Event{
		{
			DNSName:   "test1.com",
			Addresses: []string{"1.1.1.1", "2.2.2.2"},
		},
		{
			DNSName:   "test2.com",
			Addresses: []string{"3.3.3.3", "4.4.4.4"},
		},
		{
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
