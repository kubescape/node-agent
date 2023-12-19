package utils

import (
	"io"
	"os"
	"os/user"
	"strconv"

	_ "net"
	_ "unsafe"
)

// os/users package handles extracting information from users files (/etc/passwd, /etc/group) but limited to current user root only.
// Module utilizes unexported (private) functions (using go:linkname), expanding their use for custom root path.
// NOTE: code requires environment variable CGO_ENABLED = 0

//go:linkname readColonFile os/user.readColonFile
func readColonFile(r io.Reader, fn lineFunc, readCols int) (v any, err error)

//go:linkname findUserId os/user.findUserId
func findUserId(uid string, r io.Reader) (*user.User, error)

//go:linkname findGroupId os/user.findGroupId
func findGroupId(id string, r io.Reader) (*user.Group, error)

// goLlinkname lineFunc os/user lineFunc
type lineFunc func(line []byte) (v any, err error)

const userFile = "/etc/passwd"
const groupFile = "/etc/group"

var (
	userGroupCache = map[string]userGroupCacheItem{} // map[rootDir]struct{users, groups}
)

type userGroupCacheItem struct {
	users  map[string]string
	groups map[string]string
}

// getUserName checks if uid is cached, if not, it tries to find it in a users file {root}/etc/passwd.
func getUserName(uid int64, root string) (string, error) {

	// return from cache if exists
	if users, ok := userGroupCache[root]; ok {
		if username, ok := users.users[strconv.Itoa(int(uid))]; ok {
			return username, nil
		}
	}

	// find username in a users file
	username, err := lookupUsernameByUID(uid, root)
	if err != nil {
		return "", err
	}

	// cache username
	if _, ok := userGroupCache[root]; !ok {
		userGroupCache[root] = userGroupCacheItem{
			users:  map[string]string{},
			groups: map[string]string{},
		}
	}

	userGroupCache[root].users[strconv.Itoa(int(uid))] = username

	return username, nil
}

// getGroupName checks if gid is cached, if not, it tries to find it in a group file {root}/etc/group.
func getGroupName(gid int64, root string) (string, error) {

	// return from cache if exists
	if users, ok := userGroupCache[root]; ok {
		if groupname, ok := users.groups[strconv.Itoa(int(gid))]; ok {
			return groupname, nil
		}
	}

	// find groupname in a group file
	groupname, err := LookupGroupnameByGID(gid, root)
	if err != nil {
		return "", err
	}

	// cache groupname
	if _, ok := userGroupCache[root]; !ok {
		userGroupCache[root] = userGroupCacheItem{
			users:  map[string]string{},
			groups: map[string]string{},
		}
	}

	userGroupCache[root].groups[strconv.Itoa(int(gid))] = groupname

	return groupname, nil
}

// returns *Group object if gid was found in a group file {root}/etc/group, otherwise returns nil.
func lookupGroup(gid string, root string) (*user.Group, error) {
	filePath := root + groupFile
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return findGroupId(gid, f)
}

// returns group name if gid was found in a group file {root}/etc/group, otherwise returns empty string.
func LookupGroupnameByGID(gid int64, root string) (string, error) {
	groupData, err := lookupGroup(strconv.FormatInt(gid, 10), root)

	if err != nil {
		return "", err
	}

	return groupData.Name, nil

}

// returns *User object if uid was found in a users file {root}/etc/passwd, otherwise returns nil.
func lookupUser(uid string, root string) (*user.User, error) {
	filePath := root + userFile
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return findUserId(uid, f)
}

// returns username if uid was found in a users file {root}/etc/passwd, otherwise returns empty string.
func lookupUsernameByUID(uid int64, root string) (string, error) {
	userData, err := lookupUser(strconv.FormatInt(uid, 10), root)

	if err != nil {
		return "", err
	}

	return userData.Username, nil
}
