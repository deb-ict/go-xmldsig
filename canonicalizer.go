package xmldsig

import (
	"context"
	"fmt"

	"github.com/beevik/etree"
)

type CreateCanonicalizerMethod func() Canonicalizer

type Canonicalizer interface {
	GetAlgorithm() string
	Canonicalize(ctx context.Context, el *etree.Element) ([]byte, error)
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
	return nil, fmt.Errorf("no canonicalizer registered for URI: %s", uri)
}
