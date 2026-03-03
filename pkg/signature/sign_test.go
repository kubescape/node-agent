package signature

import (
	"testing"
)

type MockSignableProfile struct {
	annotations map[string]string
	uid         string
	namespace   string
	name        string
	content     interface{}
}

func NewMockSignableProfile(uid, namespace, name string, content interface{}) *MockSignableProfile {
	return &MockSignableProfile{
		annotations: make(map[string]string),
		uid:         uid,
		namespace:   namespace,
		name:        name,
		content:     content,
	}
}

func (m *MockSignableProfile) GetAnnotations() map[string]string {
	return m.annotations
}

func (m *MockSignableProfile) SetAnnotations(annotations map[string]string) {
	m.annotations = annotations
}

func (m *MockSignableProfile) GetUID() string {
	return m.uid
}

func (m *MockSignableProfile) GetNamespace() string {
	return m.namespace
}

func (m *MockSignableProfile) GetName() string {
	return m.name
}

func (m *MockSignableProfile) GetContent() interface{} {
	return m.content
}

func TestSignProfileKeyless(t *testing.T) {
	profileContent := map[string]interface{}{
		"type": "test-profile",
		"data": "test-data",
	}

	profile := NewMockSignableProfile("test-uid", "test-ns", "test-profile", profileContent)

	err := SignProfileKeyless(profile)
	if err != nil {
		t.Fatalf("SignProfileKeyless failed: %v", err)
	}

	if !IsSigned(profile) {
		t.Error("Profile should be signed")
	}

	sig, err := GetProfileSignature(profile)
	if err != nil {
		t.Fatalf("GetProfileSignature failed: %v", err)
	}

	if len(sig.Signature) == 0 {
		t.Error("Signature should not be empty")
	}

	if len(sig.Certificate) == 0 {
		t.Error("Certificate should not be empty")
	}

	if sig.Issuer == "" {
		t.Error("Issuer should not be empty for keyless signing")
	}

	if sig.Identity == "" {
		t.Error("Identity should not be empty for keyless signing")
	}
}

func TestSignProfileWithKey(t *testing.T) {
	profileContent := map[string]interface{}{
		"type": "test-profile",
		"data": "test-data",
	}

	profile := NewMockSignableProfile("test-uid", "test-ns", "test-profile-key", profileContent)

	err := SignProfileWithKey(profile)
	if err != nil {
		t.Fatalf("SignProfileWithKey failed: %v", err)
	}

	if !IsSigned(profile) {
		t.Error("Profile should be signed")
	}

	sig, err := GetProfileSignature(profile)
	if err != nil {
		t.Fatalf("GetProfileSignature failed: %v", err)
	}

	if len(sig.Signature) == 0 {
		t.Error("Signature should not be empty")
	}

	if sig.Issuer != "local" {
		t.Errorf("Expected issuer 'local', got '%s'", sig.Issuer)
	}

	if sig.Identity != "local-key" {
		t.Errorf("Expected identity 'local-key', got '%s'", sig.Identity)
	}
}

func TestIsSigned(t *testing.T) {
	tests := []struct {
		name     string
		profile  *MockSignableProfile
		expected bool
	}{
		{
			name:     "Unsigned profile",
			profile:  NewMockSignableProfile("uid", "ns", "name", map[string]string{}),
			expected: false,
		},
		{
			name:     "Profile with empty annotations",
			profile:  &MockSignableProfile{annotations: make(map[string]string)},
			expected: false,
		},
		{
			name: "Profile with signature annotation",
			profile: func() *MockSignableProfile {
				p := NewMockSignableProfile("uid", "ns", "name", map[string]string{})
				p.SetAnnotations(map[string]string{
					AnnotationSignature: "test-sig",
				})
				return p
			}(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSigned(tt.profile)
			if result != tt.expected {
				t.Errorf("IsSigned() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetProfileSignature(t *testing.T) {
	tests := []struct {
		name             string
		profile          *MockSignableProfile
		wantErr          bool
		setupSign        bool
		setupAnnotations func(*MockSignableProfile)
	}{
		{
			name:      "No annotations",
			profile:   NewMockSignableProfile("uid", "ns", "name", map[string]string{}),
			wantErr:   true,
			setupSign: false,
		},
		{
			name:    "Missing signature annotation",
			profile: NewMockSignableProfile("uid", "ns", "name", map[string]string{}),
			wantErr: true,
			setupAnnotations: func(p *MockSignableProfile) {
				p.SetAnnotations(map[string]string{
					AnnotationIssuer: "test-issuer",
				})
			},
		},
		{
			name:      "Complete signature",
			profile:   NewMockSignableProfile("uid", "ns", "name", map[string]string{}),
			wantErr:   false,
			setupSign: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupSign {
				SignProfileKeyless(tt.profile)
			} else if tt.setupAnnotations != nil {
				tt.setupAnnotations(tt.profile)
			}

			sig, err := GetProfileSignature(tt.profile)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("GetProfileSignature failed: %v", err)
			}

			if sig == nil {
				t.Fatal("Expected signature, got nil")
			}
		})
	}
}
