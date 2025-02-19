package xmldsig

import (
	"crypto"
	"crypto/x509"
	"hash"
)

type SignatureMethod int

const (
	SignatureMethod_RSA_SHA1 SignatureMethod = iota
	SignatureMethod_RSA_SHA256
	SignatureMethod_RSA_SHA384
	SignatureMethod_RSA_SHA512
)

func (s SignatureMethod) GetUri() string {
	switch s {
	case SignatureMethod_RSA_SHA1:
		return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	case SignatureMethod_RSA_SHA256:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	case SignatureMethod_RSA_SHA384:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	case SignatureMethod_RSA_SHA512:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	}
	return ""
}

func (s SignatureMethod) GetHashAlgorithm() (crypto.Hash, error) {
	switch s {
	case SignatureMethod_RSA_SHA1:
		return crypto.SHA1, nil
	case SignatureMethod_RSA_SHA256:
		return crypto.SHA256, nil
	case SignatureMethod_RSA_SHA384:
		return crypto.SHA384, nil
	case SignatureMethod_RSA_SHA512:
		return crypto.SHA512, nil
	}
	return 0, ErrInvalidSignatureMethod
}

func (s SignatureMethod) CreateHashAlgorithm() (hash.Hash, error) {
	hash, err := s.GetHashAlgorithm()
	if err != nil {
		return nil, err
	}
	return hash.New(), nil
}

func (s SignatureMethod) GetSignatureAlgorithm() (x509.SignatureAlgorithm, error) {
	switch s {
	case SignatureMethod_RSA_SHA1:
		return x509.SHA1WithRSA, nil
	case SignatureMethod_RSA_SHA256:
		return x509.SHA256WithRSA, nil
	case SignatureMethod_RSA_SHA384:
		return x509.SHA384WithRSA, nil
	case SignatureMethod_RSA_SHA512:
		return x509.SHA512WithRSA, nil
	}
	return 0, ErrInvalidSignatureMethod
}

func GetSignatureMethod(uri string) (SignatureMethod, error) {
	switch uri {
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		return SignatureMethod_RSA_SHA1, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		return SignatureMethod_RSA_SHA256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
		return SignatureMethod_RSA_SHA384, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
		return SignatureMethod_RSA_SHA512, nil
	}
	return 0, ErrInvalidSignatureMethod
}
