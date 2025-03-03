package canonicalizer

import (
	"context"
	"errors"

	"github.com/beevik/etree"
	rhdsig "github.com/russellhaering/goxmldsig"
)

type c14N10ExcCanonicalizer struct {
	prefixList string
	comments   bool
}

func NewC14N10ExcCanonicalizer() Canonicalizer {
	return &c14N10ExcCanonicalizer{
		comments: false,
	}
}

func NewC14N10ExcWithCommentsCanonicalizer() Canonicalizer {
	return &c14N10ExcCanonicalizer{
		comments: true,
	}
}

func (can *c14N10ExcCanonicalizer) GetAlgorithm() string {
	if can.comments {
		return C14N10ExcWithCommentsNamespaceUri
	} else {
		return C14N10ExcNamespaceUri
	}
}

func (can *c14N10ExcCanonicalizer) GetPrefixList() string {
	return can.prefixList
}

func (can *c14N10ExcCanonicalizer) Canonicalize(ctx context.Context, el *etree.Element) ([]byte, error) {
	canonicalizer := can.makeInternalCanonicalizer(can.prefixList)
	canonicalized, err := canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}

	return canonicalized, nil
}

func (can *c14N10ExcCanonicalizer) ReadXml(el *etree.Element) error {
	// Get the exclusive c14n prefix list
	exclusiveNamespaceElements := el.SelectElements("InclusiveNamespaces")
	if len(exclusiveNamespaceElements) > 1 {
		return errors.New("element does not contain a single InclusiveNamespaces element")
	}
	if len(exclusiveNamespaceElements) > 0 {
		can.prefixList = exclusiveNamespaceElements[0].SelectAttrValue("PrefixList", "")
	}

	return nil
}

func (can *c14N10ExcCanonicalizer) WriteXml(el *etree.Element) error {
	inclusiveNamespacesElement := etree.NewElement("InclusiveNamespaces")
	inclusiveNamespacesElement.CreateAttr("xmlns", C14N10ExcNamespaceUri)
	inclusiveNamespacesElement.CreateAttr("PrefixList", can.prefixList)
	el.AddChild(inclusiveNamespacesElement)

	return nil
}

func (can *c14N10ExcCanonicalizer) makeInternalCanonicalizer(prefixList string) rhdsig.Canonicalizer {
	if can.comments {
		return rhdsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList)
	} else {
		return rhdsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(can.prefixList)
	}
}
