package hostsensormanager

import (
	"net/http"
	"time"
)

// CloudProviderInfoSensor implements the Sensor interface for cloud provider info data
type CloudProviderInfoSensor struct {
	nodeName string
}

// NewCloudProviderInfoSensor creates a new cloud provider info sensor
func NewCloudProviderInfoSensor(nodeName string) *CloudProviderInfoSensor {
	return &CloudProviderInfoSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *CloudProviderInfoSensor) GetKind() string {
	return "CloudProviderInfo"
}

// Sense collects the cloud provider info data from the host
func (s *CloudProviderInfoSensor) Sense() (interface{}, error) {
	ret := CloudProviderInfoSpec{
		ProviderMetaDataAPIAccess: s.hasMetaDataAPIAccess(),
		NodeName:                  s.nodeName,
	}

	return &ret, nil
}

type apisURL struct {
	url     string
	headers map[string]string
}

var cloudProviderMetaDataAPIs = []apisURL{
	{
		"http://169.254.169.254/computeMetadata/v1/?alt=json&recursive=true",
		map[string]string{"Metadata-Flavor": "Google"},
	},
	{
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		map[string]string{"Metadata": "true"},
	},
	{
		"http://169.254.169.254/latest/meta-data/local-hostname",
		map[string]string{},
	},
}

func (s *CloudProviderInfoSensor) hasMetaDataAPIAccess() bool {
	client := &http.Client{
		Timeout: time.Second,
	}

	for _, req := range cloudProviderMetaDataAPIs {
		httpReq, err := http.NewRequest("GET", req.url, nil)
		if err != nil {
			continue
		}
		for k, v := range req.headers {
			httpReq.Header.Set(k, v)
		}

		res, err := client.Do(httpReq)
		if err == nil {
			defer res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return true
			}
		}
	}

	return false
}
