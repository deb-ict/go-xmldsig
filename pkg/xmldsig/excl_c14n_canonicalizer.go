package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
	rhdsig "github.com/russellhaering/goxmldsig"
	rhtree "github.com/russellhaering/goxmldsig/etreeutils"
)

type exclusiveC14NCanonicalizer struct {
	prefixList string
}

func NewExclusiveC14NCanonicalizer() Canonicalizer {
	return &exclusiveC14NCanonicalizer{}
}

func (c14n *exclusiveC14NCanonicalizer) GetPrefixList() string {
	return c14n.prefixList
}

func (c14n *exclusiveC14NCanonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	elementNsContext, err := rhtree.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	detachtedElement, err := rhtree.NSDetatch(elementNsContext, el)
	if err != nil {
		return nil, err
	}

	canonicalizer := rhdsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(c14n.prefixList)
	canonicalized, err := canonicalizer.Canonicalize(detachtedElement)
	if err != nil {
		return nil, err
	}

	return canonicalized, nil
}

func (c14n *exclusiveC14NCanonicalizer) LoadXml(el *etree.Element) error {
	// Get the exclusive c14n prefix list
	exclusiveNamespaceElements := el.SelectElements("InclusiveNamespaces")
	if len(exclusiveNamespaceElements) > 1 {
		return errors.New("element does not contain a single InclusiveNamespaces element")
	}
	if len(exclusiveNamespaceElements) > 0 {
		c14n.prefixList = exclusiveNamespaceElements[0].SelectAttrValue("PrefixList", "")
	}

	return nil
}
