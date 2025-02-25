package xmldsig

import (
	"context"

	"github.com/beevik/etree"
	rhdsig "github.com/russellhaering/goxmldsig"
)

const (
	C14N11NamespaceUri             string = "http://www.w3.org/2006/12/xml-c14n11"
	C14N11WithCommentsNamespaceUri string = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
)

type c14N11Canonicalizer struct {
	comments bool
}

func NewC14N11Canonicalizer() Canonicalizer {
	return &c14N11Canonicalizer{
		comments: false,
	}
}

func NewC14N11WithCommentsCanonicalizer() Canonicalizer {
	return &c14N11Canonicalizer{
		comments: true,
	}
}

func (can *c14N11Canonicalizer) GetAlgorithm() string {
	if can.comments {
		return C14N11WithCommentsNamespaceUri
	} else {
		return C14N11NamespaceUri
	}
}

func (can *c14N11Canonicalizer) Canonicalize(ctx context.Context, el *etree.Element) ([]byte, error) {
	canonicalizer := can.makeInternalCanonicalizer()
	canonicalized, err := canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}

	return canonicalized, nil
}

func (can *c14N11Canonicalizer) LoadXml(el *etree.Element) error {
	return nil
}

func (can *c14N11Canonicalizer) GetXml() (*etree.Element, error) {
	return nil, nil
}

func (can *c14N11Canonicalizer) makeInternalCanonicalizer() rhdsig.Canonicalizer {
	if can.comments {
		return rhdsig.MakeC14N11WithCommentsCanonicalizer()
	} else {
		return rhdsig.MakeC14N11Canonicalizer()
	}
}
