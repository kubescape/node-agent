package igbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// These are supported-input limits, not a heap or compiler-memory allowance.
// Raw OCI specs now have the same 1MiB ceiling as the existing encoded checks.
// Image metadata admits at most 16MiB per blob AND in aggregate per observation,
// counting repeated reads and inspected inline data, including failed attempts.
const (
	evidenceSpecLimit     = 1 << 20
	evidenceMetadataLimit = 16 << 20
)

var errEvidenceMetadataLimit = errors.New("runtime evidence metadata budget exceeded")

func boundedContainerSpec(ctx context.Context, c containerd.Container) (*specs.Spec, error) {
	// Refresh at the same point as containerd.Container.Spec; earlier Info is not
	// an interchangeable snapshot. Admission precedes JSON decoding, not the RPC.
	info, err := c.Info(ctx)
	if err != nil {
		return nil, err
	}
	raw := info.Spec.GetValue()
	if len(raw) > evidenceSpecLimit {
		return nil, errEvidenceMetadataLimit
	}
	var spec specs.Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

type evidenceMetadataBudget struct{ used int64 }

func (b *evidenceMetadataBudget) admit(size int64) error {
	if size < 0 || size > evidenceMetadataLimit || size > evidenceMetadataLimit-b.used {
		return errEvidenceMetadataLimit
	}
	b.used += size
	return nil
}
func (b *evidenceMetadataBudget) read(ctx context.Context, p content.Provider, d ocispec.Descriptor) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Nested Data was allocated by decoding its admitted parent. This check is
	// before inspection/use, not before that parent decoder's allocation.
	if err := b.admit(int64(len(d.Data))); err != nil {
		return nil, err
	}
	if int64(len(d.Data)) == d.Size && digest.FromBytes(d.Data) == d.Digest {
		return d.Data, nil
	}
	ra, err := p.ReaderAt(ctx, d)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ra.Close() }()
	size := ra.Size()
	// The actual content-store size controls allocation, not the descriptor.
	// The admitted maximum fits int on every supported Go architecture.
	if err := b.admit(size); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw := make([]byte, int(size))
	n, err := ra.ReadAt(raw, 0)
	if err == io.EOF {
		if int64(n) != size {
			err = io.ErrUnexpectedEOF
		} else {
			err = nil
		}
	}
	return raw, err
}

// Reuse containerd's media-type validation and decoders without allowing them
// to fetch unadmitted content. This replay may make a bounded additional copy;
// the input budget is not a claim about total decoder allocation.
type admittedEvidenceBlob struct {
	digest digest.Digest
	raw    []byte
}

func (p admittedEvidenceBlob) ReaderAt(_ context.Context, d ocispec.Descriptor) (content.ReaderAt, error) {
	if d.Digest != p.digest {
		return nil, errdefs.ErrNotFound
	}
	return admittedEvidenceReader{Reader: bytes.NewReader(p.raw)}, nil
}

type admittedEvidenceReader struct{ *bytes.Reader }

func (r admittedEvidenceReader) Size() int64 { return r.Reader.Size() }
func (admittedEvidenceReader) Close() error  { return nil }
func admittedEvidenceDescriptor(d ocispec.Descriptor) ocispec.Descriptor {
	// Force decoder reads through the exact admitted bytes, including descriptors
	// whose inline content was invalid and therefore fell back to the store.
	d.Data = nil
	d.Size = -1
	return d
}
func boundedImageRootFS(ctx context.Context, image containerd.Image) ([]digest.Digest, error) {
	return boundedRootFS(ctx, image.ContentStore(), image.Target(), image.Platform())
}

// Selection follows containerd v1.7 images.Manifest. Keep differential fixtures
// in step with dependency upgrades; Walk supplies its 10,000-reference bound.
func boundedRootFS(ctx context.Context, p content.Provider, target ocispec.Descriptor, matcher platforms.MatchComparer) ([]digest.Digest, error) {
	budget := evidenceMetadataBudget{}
	var config ocispec.Descriptor
	found, wasIndex := false, false
	err := images.Walk(ctx, images.HandlerFunc(func(ctx context.Context, d ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		switch d.MediaType {
		case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest, images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		default:
			return nil, fmt.Errorf("unexpected media type %v for %v: %w", d.MediaType, d.Digest, errdefs.ErrNotFound)
		}
		raw, err := budget.read(ctx, p, d)
		if err != nil {
			return nil, err
		}
		children, err := images.Children(ctx, admittedEvidenceBlob{digest: d.Digest, raw: raw}, admittedEvidenceDescriptor(d))
		if err != nil {
			return nil, err
		}
		switch d.MediaType {
		case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
			candidate := children[0] // Children always returns the config first, even if absent.
			if d.Digest != target.Digest && matcher != nil {
				if d.Platform != nil && !matcher.Match(*d.Platform) {
					return nil, nil
				}
				if d.Platform == nil {
					raw, err := budget.read(ctx, p, candidate)
					if err != nil {
						return nil, err
					}
					var image ocispec.Image
					if err := json.Unmarshal(raw, &image); err != nil {
						return nil, err
					}
					if !matcher.Match(platforms.Normalize(ocispec.Platform{OS: image.OS, Architecture: image.Architecture})) {
						return nil, nil
					}
				}
			}
			if !found {
				config = candidate
				found = true
			}
			return nil, nil
		default:
			if matcher == nil {
				return children, nil
			}
			selected := children[:0]
			for _, d := range children {
				if d.Platform == nil || matcher.Match(*d.Platform) {
					selected = append(selected, d)
				}
			}
			sort.SliceStable(selected, func(i, j int) bool {
				if selected[i].Platform == nil {
					return false
				}
				if selected[j].Platform == nil {
					return true
				}
				return matcher.Less(*selected[i].Platform, *selected[j].Platform)
			})
			wasIndex = true
			if len(selected) > 1 {
				selected = selected[:1]
			}
			return selected, nil
		}
	}), target)
	if err != nil {
		return nil, err
	}
	if !found {
		if wasIndex {
			return nil, fmt.Errorf("no match for platform in manifest %v: %w", target.Digest, errdefs.ErrNotFound)
		}
		return nil, fmt.Errorf("manifest %v: %w", target.Digest, errdefs.ErrNotFound)
	}
	raw, err := budget.read(ctx, p, config)
	if err != nil {
		return nil, err
	}
	return images.RootFS(ctx, admittedEvidenceBlob{digest: config.Digest, raw: raw}, admittedEvidenceDescriptor(config))
}
