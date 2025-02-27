package xmldsig

import (
	"crypto/x509"
)

type CertificateProvider interface {
	GetCertificate() (*x509.Certificate, error)
}
