package filehandler

type FileHandler interface {
	AddFile(bucket, file string)
	AddFiles(bucket string, files map[string]bool) error
	Close()
	GetFiles(container string) (map[string]bool, error)
	RemoveBucket(bucket string) error
}
