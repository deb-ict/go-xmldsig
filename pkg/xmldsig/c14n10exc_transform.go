package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
	rhtree "github.com/russellhaering/goxmldsig/etreeutils"
)

type c14N10ExcTransform struct {
	canonicalizer *c14N10ExcCanonicalizer
	reference     *Reference
}

func NewC14N10ExcTransform(reference *Reference) Transform {
	return &c14N10ExcTransform{
		canonicalizer: &c14N10ExcCanonicalizer{
			comments: false,
		},
		reference: reference,
	}
}

func NewC14N10ExcWithCommentsTransform(reference *Reference) Transform {
	return &c14N10ExcTransform{
		canonicalizer: &c14N10ExcCanonicalizer{
			comments: true,
		},
		reference: reference,
	}
}

func (t *c14N10ExcTransform) GetAlgorithm() string {
	return t.canonicalizer.GetAlgorithm()
}

func (t *c14N10ExcTransform) GetReference() *Reference {
	return t.reference
}

func (t *c14N10ExcTransform) TransformXmlElement(el *etree.Element) ([]byte, error) {
	elementNsContext, err := rhtree.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	detachtedElement, err := rhtree.NSDetatch(elementNsContext, el)
	if err != nil {
		return nil, err
	}

	return t.canonicalizer.Canonicalize(detachtedElement)
}

func (t *c14N10ExcTransform) TransformData(data []byte) ([]byte, error) {
	return nil, errors.New("exclusive c14n transform cannot be applied to data")
}

func (t *c14N10ExcTransform) LoadXml(el *etree.Element) error {
	if el == nil {
		return errors.New("element cannot be nil")
	}
	if el.Tag != "Transform" || el.NamespaceURI() != XmlDSigNamespaceUri {
		return errors.New("element is not a transform element")
	}
	t.canonicalizer.LoadXml(el)

	return nil
}
