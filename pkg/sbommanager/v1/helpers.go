package v1

import (
	"fmt"
	"os"
	"path/filepath"
)

func diskUsage(path string) int64 {
	var s int64
	dir, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return s
	}
	defer dir.Close()

	files, err := dir.Readdir(-1)
	if err != nil {
		fmt.Println(err)
		return s
	}

	for _, f := range files {
		if f.IsDir() {
			s += diskUsage(filepath.Join(path, f.Name()))
		} else {
			s += f.Size()
		}
	}
	return s
}
