package syftutil

import (
	"io/fs"
	"path"
	"path/filepath"
)

// layerMarkers holds the overlayfs markers found in one image layer's
// directory. containerd's overlay snapshotter writes them when it unpacks a
// layer, translating the OCI ".wh.<name>" and ".wh..wh..opq" tar entries:
//
//   - a whiteout (a 0/0 character device at <name>) removes <name>, and
//     everything below it, from the layers underneath;
//   - an opaque directory (xattr trusted.overlay.opaque=y, or
//     user.overlay.opaque=y with userxattr) hides the contents the layers
//     underneath have in that directory.
//
// The kernel applies them when it mounts the container's root filesystem.
// NodeResolver reads the layer directories one by one, so it has to apply
// them itself.
type layerMarkers struct {
	whiteouts map[string]struct{}
	opaque    map[string]struct{}
}

// isWhiteout reports whether p is a whiteout marker of this layer. A marker
// is not a file of the image.
func (m layerMarkers) isWhiteout(p string) bool {
	_, ok := m.whiteouts[cleanPath(p)]
	return ok
}

// hides reports whether these markers remove p from the layers underneath:
// p or one of its parent directories is whited out, or a parent directory
// is opaque.
func (m layerMarkers) hides(p string) bool {
	if len(m.whiteouts) == 0 && len(m.opaque) == 0 {
		return false
	}
	p = cleanPath(p)
	if _, ok := m.whiteouts[p]; ok {
		return true
	}
	for dir := p; dir != "/"; {
		dir = path.Dir(dir)
		if _, ok := m.whiteouts[dir]; ok {
			return true
		}
		if _, ok := m.opaque[dir]; ok {
			return true
		}
	}
	return false
}

// scanLayerMarkers walks one layer directory and collects its whiteouts and
// opaque directories, as image paths ("/usr/local/lib/node_modules/npm").
//
// Any walk error fails the scan: a directory that can't be read may hold
// markers, and missing them would put files removed by this layer back into
// the SBOM.
func scanLayerMarkers(root string) (layerMarkers, error) {
	m := layerMarkers{
		whiteouts: map[string]struct{}{},
		opaque:    map[string]struct{}{},
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		imagePath := cleanPath(filepath.ToSlash(rel))
		switch {
		case d.Type()&fs.ModeCharDevice != 0:
			if isWhiteoutDevice(p) {
				m.whiteouts[imagePath] = struct{}{}
			}
		case d.IsDir():
			if isOpaqueDir(p) {
				m.opaque[imagePath] = struct{}{}
			}
		}
		return nil
	})
	return m, err
}

func cleanPath(p string) string {
	return path.Clean("/" + p)
}
