package canonicalizer

import (
	"context"
	"fmt"

	"github.com/beevik/etree"
)

type CreateCanonicalizerMethod func() Canonicalizer

const (
	C14N10RecNamespaceUri             string = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	C14N10RecWithCommentsNamespaceUri string = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	C14N10ExcNamespaceUri             string = "http://www.w3.org/2001/10/xml-exc-c14n#"
	C14N10ExcWithCommentsNamespaceUri string = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	C14N11NamespaceUri                string = "http://www.w3.org/2006/12/xml-c14n11"
	C14N11WithCommentsNamespaceUri    string = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
)

var (
	registeredCanonicalizers map[string]CreateCanonicalizerMethod = map[string]CreateCanonicalizerMethod{
		C14N10RecNamespaceUri:             NewC14N10RecCanonicalizer,
		C14N10RecWithCommentsNamespaceUri: NewC14N10RecWithCommentsCanonicalizer,
		C14N10ExcNamespaceUri:             NewC14N10ExcCanonicalizer,
		C14N10ExcWithCommentsNamespaceUri: NewC14N10ExcWithCommentsCanonicalizer,
		C14N11NamespaceUri:                NewC14N11Canonicalizer,
		C14N11WithCommentsNamespaceUri:    NewC14N11WithCommentsCanonicalizer,
	}
)

type Canonicalizer interface {
	GetAlgorithm() string
	Canonicalize(ctx context.Context, el *etree.Element) ([]byte, error)
	LoadXml(el *etree.Element) error
	GetXml() (*etree.Element, error)
}

func RegisterCanonicalizer(uri string, method CreateCanonicalizerMethod) {
	registeredCanonicalizers[uri] = method
}

func GetCanonicalizer(uri string) (Canonicalizer, error) {
	if method, ok := registeredCanonicalizers[uri]; ok {
		return method(), nil
	}
	return nil, fmt.Errorf("no canonicalizer registered for URI: %s", uri)
}

func loadCanonicalizer(uri string, el *etree.Element) (Canonicalizer, error) {
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
