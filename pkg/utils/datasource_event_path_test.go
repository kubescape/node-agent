package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/stretchr/testify/require"
)

type openFields struct {
	fpath        *string
	fname        *string
	pid          *uint32
	fd           *uint32
	errorRaw     *int32
	dfd          *int32
	dirfd        *int32
	includeDfd   bool
	includeDirfd bool
}

func newOpenEvent(t *testing.T, f openFields) *DatasourceEvent {
	t.Helper()

	// Clear package-level fieldCaches so synthetic datasources with different
	// schema definitions do not bleed accessors.
	fieldCaches.Delete(OpenEventType)
	t.Cleanup(func() {
		fieldCaches.Delete(OpenEventType)
	})

	ds, err := datasource.New(datasource.TypeSingle, "open")
	require.NoError(t, err)

	fpathAcc, err := ds.AddField("fpath", api.Kind_String)
	require.NoError(t, err)

	fnameAcc, err := ds.AddField("fname", api.Kind_String)
	require.NoError(t, err)

	pidAcc, err := ds.AddField("proc.pid", api.Kind_Uint32)
	require.NoError(t, err)

	fdAcc, err := ds.AddField("fd", api.Kind_Uint32)
	require.NoError(t, err)

	errAcc, err := ds.AddField("error_raw", api.Kind_Int32)
	require.NoError(t, err)

	var dfdAcc, dirfdAcc datasource.FieldAccessor
	if f.includeDfd {
		dfdAcc, err = ds.AddField("dfd", api.Kind_Int32)
		require.NoError(t, err)
	}
	if f.includeDirfd {
		dirfdAcc, err = ds.AddField("dirfd", api.Kind_Int32)
		require.NoError(t, err)
	}

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })

	if f.fpath != nil {
		require.NoError(t, fpathAcc.PutString(data, *f.fpath))
	}
	if f.fname != nil {
		require.NoError(t, fnameAcc.PutString(data, *f.fname))
	}
	if f.pid != nil {
		require.NoError(t, pidAcc.PutUint32(data, *f.pid))
	}
	if f.fd != nil {
		require.NoError(t, fdAcc.PutUint32(data, *f.fd))
	}
	if f.errorRaw != nil {
		require.NoError(t, errAcc.PutInt32(data, *f.errorRaw))
	}
	if f.dfd != nil && dfdAcc != nil {
		require.NoError(t, dfdAcc.PutInt32(data, *f.dfd))
	}
	if f.dirfd != nil && dirfdAcc != nil {
		require.NoError(t, dirfdAcc.PutInt32(data, *f.dirfd))
	}

	return &DatasourceEvent{
		Data:       data,
		Datasource: ds,
		EventType:  OpenEventType,
	}
}

func str(s string) *string { return &s }

func TestDatasourceEventGetFullPath_StaleFpathFallback(t *testing.T) {
	self := uint32(os.Getpid())
	dir := t.TempDir()
	dirFile, err := os.Open(dir)
	require.NoError(t, err)
	defer func() { _ = dirFile.Close() }()
	wantDir, _ := filepath.EvalSymlinks(dir)

	t.Run("stale fpath falls back to absolute fname", func(t *testing.T) {
		event := newOpenEvent(t, openFields{
			fpath:      str("ocal.sh"), // non-absolute stale scratch buffer fragment
			fname:      str("/etc/passwd"),
			pid:        &self,
			includeDfd: true,
		})
		require.Equal(t, "/etc/passwd", event.GetFullPath())
	})

	t.Run("stale fpath falls back to relative open resolved through dfd", func(t *testing.T) {
		dfdVal := int32(dirFile.Fd())
		errVal := int32(-2) // ENOENT
		event := newOpenEvent(t, openFields{
			fpath:      str("local.sh"), // stale non-absolute fragment
			fname:      str("sub/file.txt"),
			pid:        &self,
			dfd:        &dfdVal,
			errorRaw:   &errVal,
			includeDfd: true,
		})
		wantPath := filepath.Join(wantDir, "sub/file.txt")
		require.Equal(t, wantPath, event.GetFullPath())
	})
}

func TestDatasourceEventGetFullPath_DfdRouting(t *testing.T) {
	self := uint32(os.Getpid())
	dir := t.TempDir()
	dirFile, err := os.Open(dir)
	require.NoError(t, err)
	defer func() { _ = dirFile.Close() }()
	wantDir, _ := filepath.EvalSymlinks(dir)

	t.Run("relative open resolves via dfd", func(t *testing.T) {
		dfdVal := int32(dirFile.Fd())
		errVal := int32(-2)
		event := newOpenEvent(t, openFields{
			fpath:      str(""),
			fname:      str("config.yaml"),
			pid:        &self,
			dfd:        &dfdVal,
			errorRaw:   &errVal,
			includeDfd: true,
		})
		require.Equal(t, filepath.Join(wantDir, "config.yaml"), event.GetFullPath())
	})

	t.Run("relative open resolves via legacy dirfd accessor", func(t *testing.T) {
		dirfdVal := int32(dirFile.Fd())
		errVal := int32(-2)
		event := newOpenEvent(t, openFields{
			fpath:        str(""),
			fname:        str("config.yaml"),
			pid:          &self,
			dirfd:        &dirfdVal,
			errorRaw:     &errVal,
			includeDirfd: true,
		})
		require.Equal(t, filepath.Join(wantDir, "config.yaml"), event.GetFullPath())
	})

	t.Run("regular-file dfd does not resolve and falls back to normalized raw", func(t *testing.T) {
		f, err := os.CreateTemp(dir, "regfile")
		require.NoError(t, err)
		defer func() { _ = f.Close() }()

		dfdVal := int32(f.Fd())
		errVal := int32(-20) // ENOTDIR
		event := newOpenEvent(t, openFields{
			fpath:      str(""),
			fname:      str("sub/child"),
			pid:        &self,
			dfd:        &dfdVal,
			errorRaw:   &errVal,
			includeDfd: true,
		})
		// Does not join regular file as base directory; normalizes raw instead
		require.Equal(t, "/sub/child", event.GetFullPath())
	})
}

func TestDatasourceEventGetFullPath_ErrorRawForwarding(t *testing.T) {
	self := uint32(os.Getpid())
	tmp, err := os.CreateTemp(t.TempDir(), "target")
	require.NoError(t, err)
	defer func() { _ = tmp.Close() }()
	wantTarget, _ := filepath.EvalSymlinks(tmp.Name())

	t.Run("success error_raw=0 resolves via opened fd", func(t *testing.T) {
		fdVal := uint32(tmp.Fd())
		errVal := int32(0) // success
		event := newOpenEvent(t, openFields{
			fpath:      str(""),
			fname:      str("relative/arg"),
			pid:        &self,
			fd:         &fdVal,
			errorRaw:   &errVal,
			includeDfd: true,
		})
		require.Equal(t, wantTarget, event.GetFullPath())
	})

	t.Run("failure error_raw!=0 ignores fd and resolves relative via base", func(t *testing.T) {
		fdVal := uint32(tmp.Fd())
		errVal := int32(-2) // failed openat, so fd is not the opened target
		dfdVal := AT_FDCWD
		event := newOpenEvent(t, openFields{
			fpath:      str(""),
			fname:      str("relative/arg"),
			pid:        &self,
			fd:         &fdVal,
			dfd:        &dfdVal,
			errorRaw:   &errVal,
			includeDfd: true,
		})
		cwd, _ := os.Getwd()
		require.Equal(t, filepath.Join(cwd, "relative/arg"), event.GetFullPath())
	})
}
