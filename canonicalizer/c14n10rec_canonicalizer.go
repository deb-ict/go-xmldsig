package canonicalizer

import (
	"context"

	"github.com/beevik/etree"
	rhdsig "github.com/russellhaering/goxmldsig"
	rhtree "github.com/russellhaering/goxmldsig/etreeutils"
)

type c14N10RecCanonicalizer struct {
	comments bool
}

func NewC14N10RecCanonicalizer() Canonicalizer {
	return &c14N10RecCanonicalizer{
		comments: false,
	}
}

func NewC14N10RecWithCommentsCanonicalizer() Canonicalizer {
	return &c14N10RecCanonicalizer{
		comments: true,
	}
}

func (can *c14N10RecCanonicalizer) GetAlgorithm() string {
	if can.comments {
		return C14N10RecWithCommentsNamespaceUri
	} else {
		return C14N10RecNamespaceUri
	}
}

func (can *c14N10RecCanonicalizer) Canonicalize(ctx context.Context, el *etree.Element) ([]byte, error) {
	elementNsContext, err := rhtree.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	detachtedElement, err := rhtree.NSDetatch(elementNsContext, el)
	if err != nil {
		return nil, err
	}

	canonicalizer := can.makeInternalCanonicalizer()
	canonicalized, err := canonicalizer.Canonicalize(detachtedElement)
	if err != nil {
		return nil, err
	}

	return canonicalized, nil
}

func (can *c14N10RecCanonicalizer) ReadXml(el *etree.Element) error {
	return nil
}

func (can *c14N10RecCanonicalizer) WriteXml(el *etree.Element) error {
	return nil
}

func (can *c14N10RecCanonicalizer) makeInternalCanonicalizer() rhdsig.Canonicalizer {
	if can.comments {
		return rhdsig.MakeC14N10WithCommentsCanonicalizer()
	} else {
		return rhdsig.MakeC14N10RecCanonicalizer()
	}
}
