package signature

import (
	"os"
	"testing"
)

type MockSignableObject struct {
	annotations map[string]string
	uid         string
	namespace   string
	name        string
	content     interface{}
}

func NewMockSignableObject(uid, namespace, name string, content interface{}) *MockSignableObject {
	return &MockSignableObject{
		annotations: make(map[string]string),
		uid:         uid,
		namespace:   namespace,
		name:        name,
		content:     content,
	}
}

func (m *MockSignableObject) GetAnnotations() map[string]string {
	return m.annotations
}

func (m *MockSignableObject) SetAnnotations(annotations map[string]string) {
	m.annotations = annotations
}

func (m *MockSignableObject) GetUID() string {
	return m.uid
}

func (m *MockSignableObject) GetNamespace() string {
	return m.namespace
}

func (m *MockSignableObject) GetName() string {
	return m.name
}

func (m *MockSignableObject) GetContent() interface{} {
	return m.content
}

func (m *MockSignableObject) GetUpdatedObject() interface{} {
	return m.content
}

func TestSignObjectKeyless(t *testing.T) {
	if os.Getenv("ENABLE_KEYLESS_TESTS") == "" {
		t.Skip("Skipping TestSignObjectKeyless. Set ENABLE_KEYLESS_TESTS to run.")
	}
	profileContent := map[string]interface{}{
		"type": "test-profile",
		"data": "test-data",
	}

	profile := NewMockSignableObject("test-uid", "test-ns", "test-profile", profileContent)

	err := SignObjectKeyless(profile)
	if err != nil {
		t.Fatalf("SignObjectKeyless failed: %v", err)
	}

	if !IsSigned(profile) {
		t.Error("Profile should be signed")
	}

	sig, err := GetObjectSignature(profile)
	if err != nil {
		t.Fatalf("GetObjectSignature failed: %v", err)
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

func TestSignObjectDisableKeyless(t *testing.T) {
	profileContent := map[string]interface{}{
		"type": "test-profile",
		"data": "test-data",
	}

	profile := NewMockSignableObject("test-uid", "test-ns", "test-profile-key", profileContent)

	err := SignObjectDisableKeyless(profile)
	if err != nil {
		t.Fatalf("SignObjectDisableKeyless failed: %v", err)
	}

	if !IsSigned(profile) {
		t.Error("Profile should be signed")
	}

	sig, err := GetObjectSignature(profile)
	if err != nil {
		t.Fatalf("GetObjectSignature failed: %v", err)
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
		profile  *MockSignableObject
		expected bool
	}{
		{
			name:     "Unsigned profile",
			profile:  NewMockSignableObject("uid", "ns", "name", map[string]string{}),
			expected: false,
		},
		{
			name:     "Profile with empty annotations",
			profile:  &MockSignableObject{annotations: make(map[string]string)},
			expected: false,
		},
		{
			name: "Profile with signature annotation",
			profile: func() *MockSignableObject {
				p := NewMockSignableObject("uid", "ns", "name", map[string]string{})
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

func TestGetObjectSignature(t *testing.T) {
	tests := []struct {
		name             string
		profile          *MockSignableObject
		wantErr          bool
		setupSign        bool
		setupAnnotations func(*MockSignableObject)
	}{
		{
			name:      "Nil annotations",
			profile:   &MockSignableObject{uid: "uid", namespace: "ns", name: "name", content: map[string]string{}, annotations: nil},
			wantErr:   true,
			setupSign: false,
		},
		{
			name:    "Missing signature annotation",
			profile: NewMockSignableObject("uid", "ns", "name", map[string]string{}),
			wantErr: true,
			setupAnnotations: func(p *MockSignableObject) {
				p.SetAnnotations(map[string]string{
					AnnotationIssuer: "test-issuer",
				})
			},
		},
		{
			name:      "Complete signature",
			profile:   NewMockSignableObject("uid", "ns", "name", map[string]string{}),
			wantErr:   false,
			setupSign: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupSign {
				if os.Getenv("ENABLE_KEYLESS_TESTS") == "" {
					t.Skip("Skipping subtest with SignObjectKeyless. Set ENABLE_KEYLESS_TESTS to run.")
				}
				SignObjectKeyless(tt.profile)
			} else if tt.setupAnnotations != nil {
				tt.setupAnnotations(tt.profile)
			}

			sig, err := GetObjectSignature(tt.profile)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("GetObjectSignature failed: %v", err)
			}

			if sig == nil {
				t.Fatal("Expected signature, got nil")
			}
		})
	}
}
