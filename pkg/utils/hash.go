package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
)

func CalculateSHA256FileExecHash(path string, args []string) string {
	hsh := sha256.New()
	hsh.Write([]byte(fmt.Sprintf("%s;%v", path, args)))
	hashInBytes := hsh.Sum(nil)
	return hex.EncodeToString(hashInBytes)
}

func CalculateSHA256FileOpenHash(path string) string {
	hsh := sha256.New()
	hsh.Write([]byte(path))
	hashInBytes := hsh.Sum(nil)
	return hex.EncodeToString(hashInBytes)
}

// CalculateFileHashes calculates both SHA1 and MD5 hashes of the given file.
func CalculateFileHashes(path string) (sha1Hash string, md5Hash string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	sha1Hash256 := sha1.New()
	md5Hash256 := md5.New()

	multiWriter := io.MultiWriter(sha1Hash256, md5Hash256)

	if _, err := io.Copy(multiWriter, file); err != nil {
		return "", "", err
	}

	sha1HashString := hashToString(sha1Hash256)
	md5HashString := hashToString(md5Hash256)

	return sha1HashString, md5HashString, nil
}

// hashToString converts a hash.Hash to a hexadecimal string.
func hashToString(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}
