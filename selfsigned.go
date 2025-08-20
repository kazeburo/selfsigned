package selfsigned

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type config struct {
	commonName string
	NotAfter   time.Time
}

type ConfigOption func(*config)

func CommonName(commonName string) ConfigOption {
	return func(r *config) {
		r.commonName = commonName
	}
}

func NotAfter(t time.Time) ConfigOption {
	return func(r *config) {
		r.NotAfter = t
	}
}

func TLSConfig(opts ...ConfigOption) (*tls.Config, error) {
	r := &config{
		commonName: "localhost",
		NotAfter:   time.Now().AddDate(10, 0, 0),
	}
	for _, opt := range opts {
		opt(r)
	}

	// Generate a new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: r.commonName},
		NotBefore:             time.Now(),
		NotAfter:              r.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode the private key and certificate to PEM format
	derKeyByte, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	keyBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derKeyByte,
		},
	)
	certBytesPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		},
	)

	// Create a TLS certificate
	cert, err := tls.X509KeyPair(certBytesPEM, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %v", err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}, nil
}
