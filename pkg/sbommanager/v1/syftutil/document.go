package syftutil

import (
	"encoding/json"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func ToSyftDocument(sbomSBOM *sbom.SBOM) v1beta1.SyftDocument {
	doc := syftjson.ToFormatModel(*sbomSBOM, syftjson.EncoderConfig{
		Pretty: false,
		Legacy: false,
	})
	configuration, _ := json.Marshal(doc.Descriptor.Configuration)
	metadata, _ := json.Marshal(doc.Source.Metadata)
	syftDocument := v1beta1.SyftDocument{
		Artifacts:             toSyftPackages(doc.Artifacts),
		ArtifactRelationships: toSyftRelationships(doc.ArtifactRelationships),
		Files:                 make([]v1beta1.SyftFile, len(doc.Files)),
		SyftSource: v1beta1.SyftSource{
			ID:       doc.Source.ID,
			Name:     doc.Source.Name,
			Version:  doc.Source.Version,
			Type:     doc.Source.Type,
			Metadata: metadata,
		},
		Distro: v1beta1.LinuxRelease{
			PrettyName:       doc.Distro.PrettyName,
			Name:             doc.Distro.Name,
			ID:               doc.Distro.ID,
			IDLike:           v1beta1.IDLikes(doc.Distro.IDLike),
			Version:          doc.Distro.Version,
			VersionID:        doc.Distro.VersionID,
			VersionCodename:  doc.Distro.VersionCodename,
			BuildID:          doc.Distro.BuildID,
			ImageID:          doc.Distro.ImageID,
			ImageVersion:     doc.Distro.ImageVersion,
			Variant:          doc.Distro.Variant,
			VariantID:        doc.Distro.VariantID,
			HomeURL:          doc.Distro.HomeURL,
			SupportURL:       doc.Distro.SupportURL,
			BugReportURL:     doc.Distro.BugReportURL,
			PrivacyPolicyURL: doc.Distro.PrivacyPolicyURL,
			CPEName:          doc.Distro.CPEName,
			SupportEnd:       doc.Distro.SupportEnd,
		},
		SyftDescriptor: v1beta1.SyftDescriptor{
			Name:          doc.Descriptor.Name,
			Version:       doc.Descriptor.Version,
			Configuration: configuration,
		},
		Schema: v1beta1.Schema{
			Version: doc.Schema.Version,
			URL:     doc.Schema.URL,
		},
	}
	for i := range doc.Files {
		syftDocument.Files[i].ID = doc.Files[i].ID
		syftDocument.Files[i].Location.RealPath = doc.Files[i].Location.RealPath
		syftDocument.Files[i].Location.FileSystemID = doc.Files[i].Location.FileSystemID
		syftDocument.Files[i].Metadata = toFileMetadataEntry(doc.Files[i].Metadata)
		syftDocument.Files[i].Contents = doc.Files[i].Contents
		syftDocument.Files[i].Digests = toDigests(doc.Files[i].Digests)
		syftDocument.Files[i].Licenses = toFileLicenses(doc.Files[i].Licenses)
		syftDocument.Files[i].Executable = toExecutable(doc.Files[i].Executable)
	}
	return syftDocument
}

func toSyftPackages(p []model.Package) []v1beta1.SyftPackage {
	packages := make([]v1beta1.SyftPackage, len(p))
	for i := range p {
		packages[i].ID = p[i].ID
		packages[i].Name = p[i].Name
		packages[i].Version = p[i].Version
		packages[i].Type = string(p[i].Type)
		packages[i].FoundBy = p[i].FoundBy
		packages[i].Locations = toLocations(p[i].Locations)
		packages[i].Licenses = toLicenses(p[i].Licenses)
		packages[i].Language = string(p[i].Language)
		packages[i].CPEs = toCPEs(p[i].CPEs)
		packages[i].PURL = p[i].PURL
		packages[i].Metadata, _ = json.Marshal(p[i].Metadata)
		packages[i].MetadataType = p[i].MetadataType
	}
	return packages
}

func toSyftRelationships(r []model.Relationship) []v1beta1.SyftRelationship {
	relationships := make([]v1beta1.SyftRelationship, len(r))
	for i := range r {
		relationships[i].Parent = r[i].Parent
		relationships[i].Child = r[i].Child
		relationships[i].Type = r[i].Type
	}
	return relationships
}

func toCPEs(c []model.CPE) v1beta1.CPEs {
	cpes := make(v1beta1.CPEs, len(c))
	for i := range c {
		cpes[i] = v1beta1.CPE(c[i])
	}
	return cpes
}

func toDigests(d []file.Digest) []v1beta1.Digest {
	digests := make([]v1beta1.Digest, len(d))
	for i := range d {
		digests[i].Algorithm = d[i].Algorithm
		digests[i].Value = d[i].Value
	}
	return digests
}

func toELFSecurityFeatures(f *file.ELFSecurityFeatures) *v1beta1.ELFSecurityFeatures {
	if f == nil {
		return nil
	}
	return &v1beta1.ELFSecurityFeatures{
		SymbolTableStripped:           f.SymbolTableStripped,
		StackCanary:                   f.StackCanary,
		NoExecutable:                  f.NoExecutable,
		RelocationReadOnly:            v1beta1.RelocationReadOnly(f.RelocationReadOnly),
		PositionIndependentExecutable: f.PositionIndependentExecutable,
		DynamicSharedObject:           f.DynamicSharedObject,
		LlvmSafeStack:                 f.LlvmSafeStack,
		LlvmControlFlowIntegrity:      f.LlvmControlFlowIntegrity,
		ClangFortifySource:            f.ClangFortifySource,
	}
}

func toExecutable(e *file.Executable) *v1beta1.Executable {
	if e == nil {
		return nil
	}
	return &v1beta1.Executable{
		Format:              v1beta1.ExecutableFormat(e.Format),
		HasExports:          e.HasExports,
		HasEntrypoint:       e.HasEntrypoint,
		ImportedLibraries:   e.ImportedLibraries,
		ELFSecurityFeatures: toELFSecurityFeatures(e.ELFSecurityFeatures),
	}
}

func toFileLicenseEvidence(e *model.FileLicenseEvidence) *v1beta1.FileLicenseEvidence {
	if e == nil {
		return nil
	}
	return &v1beta1.FileLicenseEvidence{
		Confidence: int64(e.Confidence),
		Offset:     int64(e.Offset),
		Extent:     int64(e.Extent),
	}
}

func toFileLicenses(l []model.FileLicense) []v1beta1.FileLicense {
	licenses := make([]v1beta1.FileLicense, len(l))
	for i := range l {
		licenses[i].Value = l[i].Value
		licenses[i].SPDXExpression = l[i].SPDXExpression
		licenses[i].Type = v1beta1.LicenseType(l[i].Type)
		licenses[i].Evidence = toFileLicenseEvidence(l[i].Evidence)
	}
	return licenses
}

func toFileMetadataEntry(m *model.FileMetadataEntry) *v1beta1.FileMetadataEntry {
	if m == nil {
		return nil
	}
	return &v1beta1.FileMetadataEntry{
		Mode:            int64(m.Mode),
		Type:            m.Type,
		LinkDestination: m.LinkDestination,
		UserID:          int64(m.UserID),
		GroupID:         int64(m.GroupID),
		MIMEType:        m.MIMEType,
		Size_:           m.Size,
	}
}

func toLicenses(l []model.License) v1beta1.Licenses {
	licenses := make(v1beta1.Licenses, len(l))
	for i := range l {
		licenses[i].Value = l[i].Value
		licenses[i].SPDXExpression = l[i].SPDXExpression
		licenses[i].Type = v1beta1.LicenseType(l[i].Type)
		licenses[i].URLs = l[i].URLs
		licenses[i].Locations = toLocations(l[i].Locations)
	}
	return licenses
}

func toLocations(l []file.Location) []v1beta1.Location {
	locations := make([]v1beta1.Location, len(l))
	for i := range l {
		locations[i].Coordinates = v1beta1.Coordinates(l[i].Coordinates)
		locations[i].VirtualPath = l[i].AccessPath
		locations[i].RealPath = l[i].RealPath
		locations[i].Annotations = l[i].Annotations
	}
	return locations
}
