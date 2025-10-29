package hostfimsensor

import "time"

type FimEventType string

const (
	FimEventTypeCreate FimEventType = "create"
	FimEventTypeChange FimEventType = "change"
	FimEventTypeRemove FimEventType = "remove"
	FimEventTypeRename FimEventType = "rename"
	FimEventTypeChmod  FimEventType = "chmod"
	FimEventTypeMove   FimEventType = "move"
)

type FimEvent interface {
	GetPath() string
	GetEventType() FimEventType
	GetFileHash() string
	GetTimestamp() time.Time
	GetUid() uint32
	GetGid() uint32
	GetMode() uint32

	// Enhanced getter methods for new fields
	GetFileSize() int64
	GetFileInode() uint64
	GetFileDevice() uint64
	GetFileMtime() time.Time
	GetFileCtime() time.Time
	GetProcessPid() uint32
	GetProcessName() string
	GetProcessArgs() []string
	GetHostName() string
	GetAgentId() string
}

type FimEventImpl struct {
	Path      string
	EventType FimEventType
	FileHash  string
	Timestamp time.Time
	Uid       uint32
	Gid       uint32
	Mode      uint32

	// Enhanced fields for richer event context
	FileSize    int64
	FileInode   uint64
	FileDevice  uint64
	FileMtime   time.Time
	FileCtime   time.Time
	ProcessPid  uint32
	ProcessName string
	ProcessArgs []string
	HostName    string
	AgentId     string
}

func (f *FimEventImpl) GetPath() string {
	return f.Path
}

func (f *FimEventImpl) GetEventType() FimEventType {
	return f.EventType
}

func (f *FimEventImpl) GetFileHash() string {
	return f.FileHash
}

func (f *FimEventImpl) GetTimestamp() time.Time {
	return f.Timestamp
}

func (f *FimEventImpl) GetUid() uint32 {
	return f.Uid
}

func (f *FimEventImpl) GetGid() uint32 {
	return f.Gid
}

func (f *FimEventImpl) GetMode() uint32 {
	return f.Mode
}

// Enhanced getter methods for new fields
func (f *FimEventImpl) GetFileSize() int64 {
	return f.FileSize
}

func (f *FimEventImpl) GetFileInode() uint64 {
	return f.FileInode
}

func (f *FimEventImpl) GetFileDevice() uint64 {
	return f.FileDevice
}

func (f *FimEventImpl) GetFileMtime() time.Time {
	return f.FileMtime
}

func (f *FimEventImpl) GetFileCtime() time.Time {
	return f.FileCtime
}

func (f *FimEventImpl) GetProcessPid() uint32 {
	return f.ProcessPid
}

func (f *FimEventImpl) GetProcessName() string {
	return f.ProcessName
}

func (f *FimEventImpl) GetProcessArgs() []string {
	return f.ProcessArgs
}

func (f *FimEventImpl) GetHostName() string {
	return f.HostName
}

func (f *FimEventImpl) GetAgentId() string {
	return f.AgentId
}
