package igbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"strings"
	"testing"

	"github.com/containerd/containerd"
	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	tasktypes "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

type limitReader struct {
	data          []byte
	size          int64
	reads, closes int
	readErr       error
}

func (r *limitReader) Size() int64  { return r.size }
func (r *limitReader) Close() error { r.closes++; return nil }
func (r *limitReader) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	n, e := bytes.NewReader(r.data).ReadAt(p, off)
	if r.readErr != nil {
		return n, r.readErr
	}
	return n, e
}

type limitProvider struct {
	reader *limitReader
	opens  int
}

func (p *limitProvider) ReaderAt(context.Context, ocispec.Descriptor) (content.ReaderAt, error) {
	p.opens++
	return p.reader, nil
}

func TestEvidenceMetadataReaderAdmission(t *testing.T) {
	ctx := context.Background()
	for _, size := range []int64{-1, evidenceMetadataLimit + 1, 1 << 62} {
		p := &limitProvider{reader: &limitReader{size: size}}
		b := evidenceMetadataBudget{}
		_, err := b.read(ctx, p, ocispec.Descriptor{})
		require.ErrorIs(t, err, errEvidenceMetadataLimit)
		require.Zero(t, p.reader.reads)
		require.Equal(t, 1, p.reader.closes)
	}
	p := &limitProvider{reader: &limitReader{data: make([]byte, evidenceMetadataLimit), size: evidenceMetadataLimit}}
	b := evidenceMetadataBudget{}
	got, err := b.read(ctx, p, ocispec.Descriptor{Size: 1})
	require.NoError(t, err)
	require.Len(t, got, evidenceMetadataLimit)
	require.Equal(t, int64(evidenceMetadataLimit), b.used)
	p.reader = &limitReader{data: []byte("x"), size: 1}
	_, err = b.read(ctx, p, ocispec.Descriptor{})
	require.ErrorIs(t, err, errEvidenceMetadataLimit)
	require.Zero(t, p.reader.reads)
	require.Equal(t, 1, p.reader.closes)
	for _, tc := range []struct {
		name          string
		data          string
		size          int64
		readErr, want error
	}{
		{"short", "x", 2, nil, io.ErrUnexpectedEOF}, {"exact-eof", "xx", 2, io.EOF, nil}, {"failed", "xx", 2, io.ErrClosedPipe, io.ErrClosedPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &limitProvider{reader: &limitReader{data: []byte(tc.data), size: tc.size, readErr: tc.readErr}}
			b := evidenceMetadataBudget{}
			_, err := b.read(ctx, p, ocispec.Descriptor{Size: 999})
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, tc.size, b.used)
			require.Equal(t, 1, p.reader.closes)
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	p = &limitProvider{reader: &limitReader{size: 1}}
	_, err = (&evidenceMetadataBudget{}).read(canceled, p, ocispec.Descriptor{})
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, p.opens)
}
func TestEvidenceMetadataInlineAdmission(t *testing.T) {
	data := []byte("config")
	desc := ocispec.Descriptor{Data: data, Size: int64(len(data)), Digest: digest.FromBytes(data)}
	p := &limitProvider{reader: &limitReader{data: []byte("store"), size: 5}}
	b := evidenceMetadataBudget{}
	got, err := b.read(context.Background(), p, desc)
	require.NoError(t, err)
	require.Equal(t, data, got)
	require.Zero(t, p.opens)
	desc.Size++ // Invalid inline still falls back, charging both inspected attempts.
	got, err = b.read(context.Background(), p, desc)
	require.NoError(t, err)
	require.Equal(t, []byte("store"), got)
	require.Equal(t, int64(17), b.used)
	b.used = evidenceMetadataLimit - int64(len(data)) + 1
	_, err = b.read(context.Background(), p, desc)
	require.ErrorIs(t, err, errEvidenceMetadataLimit)
	require.Equal(t, 1, p.opens)
	huge := make([]byte, evidenceMetadataLimit+1)
	_, err = (&evidenceMetadataBudget{}).read(context.Background(), p, ocispec.Descriptor{Data: huge})
	require.ErrorIs(t, err, errEvidenceMetadataLimit)
	require.Equal(t, 1, p.opens)
}

type metadataFixture struct {
	blobs map[digest.Digest][]byte
	reads map[digest.Digest]int
}

func newMetadataFixture() *metadataFixture {
	return &metadataFixture{blobs: map[digest.Digest][]byte{}, reads: map[digest.Digest]int{}}
}
func (f *metadataFixture) ReaderAt(_ context.Context, d ocispec.Descriptor) (content.ReaderAt, error) {
	b, ok := f.blobs[d.Digest]
	if !ok {
		return nil, errdefs.ErrNotFound
	}
	f.reads[d.Digest]++
	return &limitReader{data: b, size: int64(len(b))}, nil
}
func (f *metadataFixture) blob(mt string, b []byte) ocispec.Descriptor {
	d := ocispec.Descriptor{MediaType: mt, Digest: digest.FromBytes(b), Size: int64(len(b))}
	f.blobs[d.Digest] = b
	return d
}
func (f *metadataFixture) document(t *testing.T, mt string, v any) ocispec.Descriptor {
	t.Helper()
	b, e := json.Marshal(v)
	require.NoError(t, e)
	return f.blob(mt, b)
}
func (f *metadataFixture) manifest(t *testing.T, arch, tag, mt string) ocispec.Descriptor {
	c := f.document(t, ocispec.MediaTypeImageConfig, ocispec.Image{Platform: ocispec.Platform{OS: "linux", Architecture: arch}, RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.FromString(tag)}}})
	return f.document(t, mt, ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: mt, Config: c})
}
func (f *metadataFixture) index(t *testing.T, ds ...ocispec.Descriptor) ocispec.Descriptor {
	return f.document(t, ocispec.MediaTypeImageIndex, ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: ds})
}
func compareBoundedRootFS(t *testing.T, f *metadataFixture, d ocispec.Descriptor, m platforms.MatchComparer) {
	t.Helper()
	old, oldErr := (&images.Image{Target: d}).RootFS(context.Background(), f, m)
	got, err := boundedRootFS(context.Background(), f, d, m)
	if oldErr == nil {
		require.NoError(t, err)
		require.Equal(t, old, got)
	} else {
		require.Error(t, err)
		require.Equal(t, errdefs.IsNotFound(oldErr), errdefs.IsNotFound(err))
		require.Equal(t, errdefs.IsResourceExhausted(oldErr), errdefs.IsResourceExhausted(err))
	}
}
func TestEvidenceRootFSDifferential(t *testing.T) {
	for _, kind := range []string{"direct-oci", "direct-docker", "root-platform-ignored", "explicit-match", "no-match", "config-fallback", "config-mismatch", "stable-order", "nested", "nil-matcher", "nested-inline", "schema1", "manifest-index-confusion", "unknown", "malformed", "missing-config", "empty-index", "docker-index", "index-manifest-confusion", "invalid-inline-fallback", "nil-matcher-later-error", "inline-config"} {
		t.Run(kind, func(t *testing.T) {
			f := newMetadataFixture()
			a := f.manifest(t, "amd64", "a", ocispec.MediaTypeImageManifest)
			b := f.manifest(t, "amd64", "b", ocispec.MediaTypeImageManifest)
			m := platforms.Only(ocispec.Platform{OS: "linux", Architecture: "amd64"})
			d := a
			amd := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
			arm := &ocispec.Platform{OS: "linux", Architecture: "arm64"}
			switch kind {
			case "direct-docker":
				d = f.manifest(t, "amd64", "docker", images.MediaTypeDockerSchema2Manifest)
			case "root-platform-ignored":
				d.Platform = arm
			case "explicit-match":
				a.Platform = amd
				d = f.index(t, a)
			case "no-match":
				a.Platform = arm
				d = f.index(t, a)
			case "config-fallback":
				d = f.index(t, a)
			case "config-mismatch":
				a = f.manifest(t, "arm64", "arm", ocispec.MediaTypeImageManifest)
				d = f.index(t, a)
			case "stable-order":
				a.Platform = amd
				b.Platform = amd
				d = f.index(t, b, a)
			case "nested":
				d = f.index(t, f.index(t, a))
			case "nil-matcher":
				m = nil
				d = f.index(t, b, a)
			case "nested-inline":
				a.Data = f.blobs[a.Digest]
				delete(f.blobs, a.Digest)
				d = f.index(t, a)
			case "schema1":
				d = f.blob(ocispec.MediaTypeImageManifest, []byte(`{"fsLayers":[]}`))
			case "manifest-index-confusion":
				d = f.blob(ocispec.MediaTypeImageManifest, []byte(`{"manifests":[]}`))
			case "unknown":
				d.MediaType = "unknown"
			case "malformed":
				d = f.blob(ocispec.MediaTypeImageManifest, []byte(`{`))
			case "missing-config":
				d = f.document(t, ocispec.MediaTypeImageManifest, ocispec.Manifest{})
			case "empty-index":
				d = f.index(t)
			case "docker-index":
				d = f.document(t, images.MediaTypeDockerSchema2ManifestList, ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{a}})
			case "index-manifest-confusion":
				d = f.blob(ocispec.MediaTypeImageIndex, []byte(`{"config":{}}`))
			case "invalid-inline-fallback":
				a.Data = []byte("invalid")
				d = f.index(t, a)
			case "nil-matcher-later-error":
				m = nil
				bad := f.blob(ocispec.MediaTypeImageManifest, []byte(`{`))
				d = f.index(t, a, bad)
			case "inline-config":
				c := f.document(t, ocispec.MediaTypeImageConfig, ocispec.Image{Platform: ocispec.Platform{OS: "linux", Architecture: "amd64"}, RootFS: ocispec.RootFS{DiffIDs: []digest.Digest{digest.FromString("inline")}}})
				c.Data = f.blobs[c.Digest]
				delete(f.blobs, c.Digest)
				a = f.document(t, ocispec.MediaTypeImageManifest, ocispec.Manifest{Config: c})
				d = f.index(t, a)
			}
			compareBoundedRootFS(t, f, d, m)
		})
	}
}

type specContainer struct {
	containerd.Container
	raw   []byte
	calls int
}

func (c *specContainer) Info(context.Context, ...containerd.InfoOpts) (containers.Container, error) {
	c.calls++
	return containers.Container{Spec: &anypb.Any{Value: c.raw}}, nil
}
func TestEvidenceSpecPredecode(t *testing.T) {
	for _, n := range []int{evidenceSpecLimit, evidenceSpecLimit + 1} {
		c := &specContainer{raw: []byte(`{}` + strings.Repeat(" ", n-2))}
		got, err := boundedContainerSpec(context.Background(), c)
		require.Equal(t, 1, c.calls)
		if n == evidenceSpecLimit {
			require.NoError(t, err)
			require.NotNil(t, got)
		} else {
			require.ErrorIs(t, err, errEvidenceMetadataLimit)
			require.Nil(t, got)
		}
	}
	c := &specContainer{raw: bytes.Repeat([]byte("!"), evidenceSpecLimit+1)}
	_, err := boundedContainerSpec(context.Background(), c)
	require.ErrorIs(t, err, errEvidenceMetadataLimit) // Not JSON syntax error: refusal precedes decoding.
	require.False(t, transientImageEvidenceRetrieval(err))
	var unavailable *imageEvidenceUnavailable
	require.False(t, errors.As(err, &unavailable))
}

func TestEvidenceRootFSRepeatedConfigAndTraversalLimits(t *testing.T) {
	f := newMetadataFixture()
	raw := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}` + strings.Repeat(" ", evidenceMetadataLimit/2))
	c := f.blob(ocispec.MediaTypeImageConfig, raw)
	m := f.document(t, ocispec.MediaTypeImageManifest, ocispec.Manifest{Config: c})
	target := f.index(t, m)
	_, err := boundedRootFS(context.Background(), f, target, platforms.Only(ocispec.Platform{OS: "linux", Architecture: "amd64"}))
	require.ErrorIs(t, err, errEvidenceMetadataLimit)
	require.Equal(t, 2, f.reads[c.Digest], "second reader is opened to obtain actual size, then refused before reading")
	// This is the selected dependency's reference bound, not an added limit.
	repeated := make([]ocispec.Descriptor, 10000)
	for i := range repeated {
		repeated[i] = m
	}
	target = f.index(t, repeated...)
	compareBoundedRootFS(t, f, target, nil)
	_, err = boundedRootFS(context.Background(), f, target, nil)
	require.True(t, errdefs.IsResourceExhausted(err))
}

func TestEvidenceAdmittedBlobCannotFetchOtherContent(t *testing.T) {
	p := admittedEvidenceBlob{digest: digest.FromString("one"), raw: []byte("one")}
	_, err := p.ReaderAt(context.Background(), ocispec.Descriptor{Digest: digest.FromString("two")})
	require.ErrorIs(t, err, errdefs.ErrNotFound)
}

// Real containerd services are substituted only at the transport boundary.
// Evidence, acquisition and re-attestation all execute their production code.
type limitContainerStore struct {
	containers.Store
	spec []byte
	gets int
}

func (s *limitContainerStore) Get(_ context.Context, id string) (containers.Container, error) {
	s.gets++
	return containers.Container{ID: id, Image: "fixture", Spec: &anypb.Any{Value: s.spec}}, nil
}

type limitTaskClient struct{ tasks.TasksClient }

func (limitTaskClient) Get(_ context.Context, r *tasks.GetRequest, _ ...grpc.CallOption) (*tasks.GetResponse, error) {
	return &tasks.GetResponse{Process: &tasktypes.Process{ID: r.ContainerID, Pid: 42, Status: tasktypes.Status_RUNNING}}, nil
}

type limitImageStore struct {
	images.Store
	target ocispec.Descriptor
}

func (s limitImageStore) Get(context.Context, string) (images.Image, error) {
	return images.Image{Name: "fixture", Target: s.target}, nil
}

type limitContentStore struct {
	content.Store
	fixture   *metadataFixture
	oversized digest.Digest
	rejected  *limitReader
}

func (s *limitContentStore) ReaderAt(ctx context.Context, d ocispec.Descriptor) (content.ReaderAt, error) {
	if d.Digest == s.oversized {
		s.rejected = &limitReader{size: evidenceMetadataLimit + 1}
		return s.rejected, nil
	}
	return s.fixture.ReaderAt(ctx, d)
}
func TestEvidenceLimitsRealEntryAcquisitionAndReattestation(t *testing.T) {
	for _, kind := range []string{"spec", "config"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newMetadataFixture()
			config := fixture.blob(ocispec.MediaTypeImageConfig, []byte(`{}`))
			target := fixture.document(t, ocispec.MediaTypeImageManifest, ocispec.Manifest{Config: config})
			store := &limitContainerStore{spec: []byte(`{}`)}
			cs := &limitContentStore{fixture: fixture}
			if kind == "spec" {
				store.spec = bytes.Repeat([]byte("!"), evidenceSpecLimit+1)
			} else {
				cs.oversized = config.Digest
			}
			client, err := containerd.New("", containerd.WithServices(containerd.WithContainerStore(store), containerd.WithTaskClient(limitTaskClient{}), containerd.WithImageStore(limitImageStore{target: target}), containerd.WithContentStore(cs)))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, client.Close()) })
			source := &containerdImageSource{client: client}
			process := &linuxLease{identity: sandboxpolicy.Binding{Runtime: "containerd", ContainerID: strings.Repeat("a", 64), PID: 42}}
			_, err = acquireImageEvidence(context.Background(), source, process, "/", ImageIndexLimits{})
			require.ErrorIs(t, err, errEvidenceMetadataLimit)
			require.GreaterOrEqual(t, store.gets, 3, "Spec must refresh metadata at its original call point")
			lease := &trustedImageLease{source: source, process: process, Complete: true}
			err = lease.CheckContext(context.Background())
			require.ErrorIs(t, err, errEvidenceMetadataLimit)
			require.False(t, lease.Complete)
			require.Same(t, err, lease.failure)
			before := store.gets
			require.ErrorIs(t, lease.CheckContext(context.Background()), errEvidenceMetadataLimit)
			require.Equal(t, before, store.gets, "unsupported metadata must be sticky, not transport-unavailable")
			if kind == "config" {
				require.NotNil(t, cs.rejected)
				require.Zero(t, cs.rejected.reads)
				require.Equal(t, 1, cs.rejected.closes)
			}
		})
	}
}

func TestEvidenceLimitsRealCallSites(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "imageevidence.go", nil, 0)
	require.NoError(t, err)
	seen := map[string]int{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Evidence" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok {
				seen[id.Name]++
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Spec" || sel.Sel.Name == "RootFS") {
				t.Errorf("unbounded decoder in actual Evidence: %s", sel.Sel.Name)
			}
			return true
		})
	}
	require.Equal(t, 2, seen["boundedContainerSpec"])
	require.Equal(t, 1, seen["boundedImageRootFS"])
}
