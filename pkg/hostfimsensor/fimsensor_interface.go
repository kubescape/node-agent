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
}

type FimEventImpl struct {
	Path      string
	EventType FimEventType
	FileHash  string
	Timestamp time.Time
	Uid       uint32
	Gid       uint32
	Mode      uint32
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
