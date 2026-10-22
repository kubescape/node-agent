//go:build experimental_signing

package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/stretchr/testify/require"
)

func selfSigned(t *testing.T, key *ecdsa.PrivateKey, cn string, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, Issuer: pkix.Name{CommonName: cn + "-issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSignerIdentity_IsThePublicKeyFingerprintAndNothingElse(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	idA1, err := signerIdentity(&signature.Signature{Certificate: selfSigned(t, keyA, "vendor", time.Now().Add(time.Hour))})
	require.NoError(t, err)
	idA2, err := signerIdentity(&signature.Signature{Certificate: selfSigned(t, keyA, "someone-else", time.Now().Add(-time.Minute))})
	require.NoError(t, err)
	idB, err := signerIdentity(&signature.Signature{Certificate: selfSigned(t, keyB, "vendor", time.Now().Add(time.Hour))})
	require.NoError(t, err)

	require.Equal(t, idA1, idA2, "subject, issuer and expiry play no part: the same key is the same signer")
	require.NotEqual(t, idA1, idB, "the same name with another key is another signer")
	require.Regexp(t, `^key:[0-9a-f]{64}$`, idA1)

	_, err = signerIdentity(&signature.Signature{})
	require.Error(t, err, "a signature without a certificate has no identity")
	_, err = signerIdentity(nil)
	require.Error(t, err)

	require.True(t, ClassPolicy{Signers: []string{idA1}}.allowsSigner(idA2), "trust is pinned to the key fingerprint")
	require.False(t, ClassPolicy{Signers: []string{idA1}}.allowsSigner(idB))
}
