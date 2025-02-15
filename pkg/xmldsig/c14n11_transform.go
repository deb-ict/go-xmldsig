package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
	rhtree "github.com/russellhaering/goxmldsig/etreeutils"
)

type c14N11Transform struct {
	canonicalizer *c14N11Canonicalizer
	reference     *Reference
}

func (t *c14N11Transform) GetAlgorithm() string {
	return t.canonicalizer.GetAlgorithm()
}

func (t *c14N11Transform) GetReference() *Reference {
	return t.reference
}

func (t *c14N11Transform) TransformXmlElement(el *etree.Element) ([]byte, error) {
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

func (t *c14N11Transform) TransformData(data []byte) ([]byte, error) {
	return nil, errors.New("exclusive c14n transform cannot be applied to data")
}

func (t *c14N11Transform) LoadXml(el *etree.Element) error {
	if el == nil {
		return errors.New("element cannot be nil")
	}
	if el.Tag != "Transform" || el.NamespaceURI() != XmlDSigNamespaceUri {
		return errors.New("element is not a transform element")
	}
	t.canonicalizer.LoadXml(el)

	return nil
}

func NewC14N11Transform(reference *Reference) Transform {
	return &c14N11Transform{
		canonicalizer: &c14N11Canonicalizer{
			comments: false,
		},
		reference: reference,
	}
}

func NewC14N11WithCommentsTransform(reference *Reference) Transform {
	return &c14N11Transform{
		canonicalizer: &c14N11Canonicalizer{
			comments: true,
		},
		reference: reference,
	}
}
