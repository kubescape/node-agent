package datastructures

// FileInfo holds information about a file
type FileInfo struct {
	// Ownership information
	Ownership *FileOwnership `json:"ownership"`

	// The path of the file
	// Example: /etc/kubernetes/manifests/kube-apiserver.yaml
	Path string `json:"path"`

	// Content of the file
	Content     []byte `json:"content,omitempty"`
	Permissions int    `json:"permissions"`
}

// User
// FileOwnership holds the ownership of a file
type FileOwnership struct {
	// Error if couldn't get owner's file or uid/gid
	Err string `json:"err,omitempty"`

	// UID owner of the files
	UID int64 `json:"uid"`

	// GID of the file
	GID int64 `json:"gid"`

	// username extracted by UID from {root}/etc/passwd
	Username string `json:"username"`

	// group name extracted by GID from {root}/etc/group
	Groupname string `json:"groupname"`
}
