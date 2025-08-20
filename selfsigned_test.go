package selfsigned

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTLSConfig_Default(t *testing.T) {
	cfg, err := TLSConfig()
	assert.NoError(t, err, "unexpected error")
	assert.NotNil(t, cfg, "expected non-nil tls.Config")
	assert.Greater(t, len(cfg.Certificates), 0, "expected at least one certificate in tls.Config")
	assert.True(t, cfg.InsecureSkipVerify, "expected InsecureSkipVerify to be true")
}

func TestTLSConfig_WithOptions(t *testing.T) {
	commonName := "example.com"
	notAfter := time.Now().AddDate(1, 0, 0).Truncate(time.Second)
	cfg, err := TLSConfig(CommonName(commonName), NotAfter(notAfter))
	assert.NoError(t, err, "unexpected error")
	assert.NotNil(t, cfg, "expected non-nil tls.Config")
	assert.Equal(t, len(cfg.Certificates), 1, "expected exactly one certificate in tls.Config")
	assert.NotNil(t, cfg.Certificates[0].Certificate, "expected certificate to be non-nil")
	assert.Equal(t, cfg.Certificates[0].Leaf.Subject.CommonName, commonName, "expected certificate CommonName to match")
	assert.Equal(t, cfg.Certificates[0].Leaf.NotAfter, notAfter.UTC(), "expected certificate NotAfter to match")
	assert.NotNil(t, cfg.Certificates[0].PrivateKey, "expected private key to be non-nil")
	_, ok := cfg.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected private key to be of type *ecdsa.PrivateKey")
}
