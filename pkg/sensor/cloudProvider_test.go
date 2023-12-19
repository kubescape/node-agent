package sensor

import (
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func Test_hasMetaDataAPIAccess(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Exact URL match
	httpmock.RegisterResponder("GET", "http://www.mygoodurl.com",
		httpmock.NewStringResponder(200, `[{"id": 1, "name": "My Good URL"}]`))

	CloudProviderMetaDataAPIs = []APIsURLs{
		{
			"http://www.mygoodurl.com",
			map[string]string{},
		},
		{
			"http://10.20.30.100",
			map[string]string{},
		},
	}

	t.Run("Has Access", func(t *testing.T) {
		res := hasMetaDataAPIAccess()
		assert.Equal(t, true, res)
	})

	CloudProviderMetaDataAPIs = []APIsURLs{
		{
			"http://10.20.30.100",
			map[string]string{},
		},
	}

	t.Run("No Access", func(t *testing.T) {
		res := hasMetaDataAPIAccess()
		assert.Equal(t, false, res)
	})
}
