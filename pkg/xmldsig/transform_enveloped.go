package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
)

const (
	EnvelopedSignatureTransform string = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

type envelopedSignatureTransform struct {
	reference *Reference
}

func (t *envelopedSignatureTransform) GetAlgorithm() string {
	return EnvelopedSignatureTransform
}

func (t *envelopedSignatureTransform) GetReference() *Reference {
	return t.reference
}

func (t *envelopedSignatureTransform) LoadXml(el *etree.Element) error {
	return nil
}

func (t *envelopedSignatureTransform) TransformXmlElement(el *etree.Element) ([]byte, error) {
	return nil, errors.New("enveloped signature transform cannot be applied to element")
}

func (t *envelopedSignatureTransform) TransformData(data []byte) ([]byte, error) {
	return nil, errors.New("enveloped signature transform cannot be applied to data")
}

func NewEnvelopedSignatureTransform(reference *Reference) Transform {
	return &envelopedSignatureTransform{
		reference: reference,
	}
}
