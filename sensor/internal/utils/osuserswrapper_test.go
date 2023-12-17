package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// func is testing if the name return as wheel or root
func isValidaName(name string) bool {
	return name == "root" || name == "wheel" || name == "daemon"
}

func TestGetUserName(t *testing.T) {
	userGroupCache = map[string]userGroupCacheItem{}
	// regular
	t.Run("regular", func(t *testing.T) {
		name, _ := getUserName(0, "testdata")
		if !isValidaName(name) {
			t.Errorf("Wrong name '%s'", name)
		}
		assert.Contains(t, userGroupCache, "testdata")
		assert.Contains(t, userGroupCache["testdata"].users, "0")

		groups := userGroupCache["testdata"].groups["0"]

		if len(groups) != 0 && !isValidaName(groups) {
			t.Errorf("Wrong group '%s'", groups)
		}
	})

	// cached
	t.Run("cached", func(t *testing.T) {
		userGroupCache["foo"] = userGroupCacheItem{
			users:  map[string]string{"0": "bar"},
			groups: map[string]string{},
		}
		name, _ := getUserName(0, "foo")
		assert.Equal(t, "bar", name)
	})
}

func TestGetGroupName(t *testing.T) {
	userGroupCache = map[string]userGroupCacheItem{}

	// regular
	t.Run("regular", func(t *testing.T) {
		name, _ := getGroupName(0, "testdata")
		if !isValidaName(name) {
			t.Errorf("Wrong name '%s'", name)
		}

		// assert.Equal(t, "root", name)
		assert.Contains(t, userGroupCache, "testdata")
		assert.Contains(t, userGroupCache["testdata"].groups, "0")
		if !isValidaName(userGroupCache["testdata"].groups["0"]) {
			t.Errorf("Wrong name '%s'", userGroupCache["testdata"].groups["0"])
		}
	})

	// cached
	t.Run("cached", func(t *testing.T) {
		userGroupCache["foo"] = userGroupCacheItem{
			users:  map[string]string{},
			groups: map[string]string{"0": "bar"},
		}
		name, _ := getGroupName(0, "foo")
		assert.Equal(t, "bar", name)
	})
}

func Test_LookupUsernameByUID(t *testing.T) {
	uid_tests := []struct {
		name        string
		root        string
		uid         int64
		expectedRes string
		wantErr     bool
	}{
		{
			name:    "testdata_uid_exists",
			root:    "testdata",
			uid:     0,
			wantErr: false,
		},
		{
			name:    "testdata_uid_not_exists",
			root:    "testdata",
			uid:     10,
			wantErr: true,
		},
		{
			name:    "testdata_file_not_exists",
			root:    "testdata/bla",
			uid:     10,
			wantErr: true,
		},
		{
			name:    "root_uid_exists",
			root:    "/",
			uid:     0,
			wantErr: false,
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			username, err := lookupUsernameByUID(tt.uid, tt.root)

			if err != nil {
				if !tt.wantErr {
					assert.NoError(t, err)
				}

			} else {
				assert.NoError(t, err)
				if !isValidaName(username) {
					t.Errorf("Wrong name")
				}
			}

		})
	}
}

func Test_LookupGroupByUID(t *testing.T) {

	uid_tests := []struct {
		name        string
		root        string
		gid         int64
		expectedRes string
		wantErr     bool
	}{
		{
			name:        "testdata_uid_exists",
			root:        "testdata",
			gid:         1,
			expectedRes: "daemon",
			wantErr:     false,
		},
		{
			name:    "testdata_uid_not_exists",
			root:    "testdata",
			gid:     10,
			wantErr: true,
		},
		{
			name:    "testdata_file_not_exists",
			root:    "testdata/bla",
			gid:     10,
			wantErr: true,
		},
		{
			name:    "root_uid_exists",
			root:    "/",
			gid:     0,
			wantErr: false,
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			groupname, err := LookupGroupnameByGID(tt.gid, tt.root)

			if err != nil {
				if !tt.wantErr {
					assert.NoError(t, err)
				}

			} else {
				assert.NoError(t, err)
				if !isValidaName(groupname) {
					t.Errorf("Wrong name '%s'", groupname)
				}
			}

		})
	}

}
