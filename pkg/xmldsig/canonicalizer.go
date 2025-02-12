package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
)

type CreateCanonicalizerMethod func() Canonicalizer

type Canonicalizer interface {
	Canonicalize(el *etree.Element) ([]byte, error)
	LoadXml(el *etree.Element) error
}

func RegisterCanonicalizer(uri string, method CreateCanonicalizerMethod) {
	registeredCanonicalizers[uri] = method
}

func GetCanonicalizer(uri string, el *etree.Element) (Canonicalizer, error) {
	if method, ok := registeredCanonicalizers[uri]; ok {
		m := method()
		err := m.LoadXml(el)
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	return nil, errors.New("transform not found")
}
