package xmldsig

import (
	"crypto"
	"hash"
)

type DigestMethodEnum int

const (
	DigestMethod_SHA1 DigestMethodEnum = iota
	DigestMethod_SHA256
	DigestMethod_SHA384
	DigestMethod_SHA512
)

func (d DigestMethodEnum) GetUri() string {
	switch d {
	case DigestMethod_SHA1:
		return "http://www.w3.org/2000/09/xmldsig#sha1"
	case DigestMethod_SHA256:
		return "http://www.w3.org/2001/04/xmlenc#sha256"
	case DigestMethod_SHA384:
		return "http://www.w3.org/2001/04/xmldsig-more#sha384"
	case DigestMethod_SHA512:
		return "http://www.w3.org/2001/04/xmlenc#sha512"
	}
	return ""
}

func (d DigestMethodEnum) GetHashAlgorithm() (crypto.Hash, error) {
	switch d {
	case DigestMethod_SHA1:
		return crypto.SHA1, nil
	case DigestMethod_SHA256:
		return crypto.SHA256, nil
	case DigestMethod_SHA384:
		return crypto.SHA384, nil
	case DigestMethod_SHA512:
		return crypto.SHA512, nil
	}
	return 0, ErrInvalidDigestMethod
}

func (d DigestMethodEnum) CreateHashAlgorithm() (hash.Hash, error) {
	hash, err := d.GetHashAlgorithm()
	if err != nil {
		return nil, err
	}
	return hash.New(), nil
}

func GetDigestMethod(uri string) (DigestMethodEnum, error) {
	switch uri {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		return DigestMethod_SHA1, nil
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		return DigestMethod_SHA256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#sha384":
		return DigestMethod_SHA384, nil
	case "http://www.w3.org/2001/04/xmlenc#sha512":
		return DigestMethod_SHA512, nil
	}
	return 0, ErrInvalidDigestMethod
}
