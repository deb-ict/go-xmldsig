package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
)

const (
	ExclusiveC14NTransformNamespaceUri string = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

type exclusiveC14NTransform struct {
	canonicalizer *exclusiveC14NCanonicalizer
	reference     *Reference
}

func (t *exclusiveC14NTransform) TransformXmlElement(el *etree.Element) ([]byte, error) {
	return t.canonicalizer.Canonicalize(el)
}

func (t *exclusiveC14NTransform) TransformData(data []byte) ([]byte, error) {
	return nil, errors.New("exclusive c14n transform cannot be applied to data")
}

func (t *exclusiveC14NTransform) GetAlgorithm() string {
	return ExclusiveC14NTransformNamespaceUri
}

func (t *exclusiveC14NTransform) Reference() *Reference {
	return t.reference
}

func (t *exclusiveC14NTransform) LoadXml(el *etree.Element) error {
	if el == nil {
		return errors.New("element cannot be nil")
	}
	if el.Tag != "Transform" || el.NamespaceURI() != XmlDSigNamespaceUri {
		return errors.New("element is not a transform element")
	}
	t.canonicalizer.LoadXml(el)

	return nil
}

func NewExclusiveC14NTransform(reference *Reference) Transform {
	return &exclusiveC14NTransform{
		canonicalizer: &exclusiveC14NCanonicalizer{},
		reference:     reference,
	}
}
