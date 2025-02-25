package xmldsig

import (
	"context"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xmldsig/canonicalizer"
	rhtree "github.com/russellhaering/goxmldsig/etreeutils"
)

type c14N10RecTransform struct {
	canonicalizer canonicalizer.Canonicalizer
	reference     *Reference
}

func NewC14N10RecTransform(reference *Reference) TransformMethod {
	return &c14N10RecTransform{
		canonicalizer: canonicalizer.NewC14N10RecCanonicalizer(),
		reference:     reference,
	}
}

func NewC14N10RecWithCommentsTransform(reference *Reference) TransformMethod {
	return &c14N10RecTransform{
		canonicalizer: canonicalizer.NewC14N10RecWithCommentsCanonicalizer(),
		reference:     reference,
	}
}

func (t *c14N10RecTransform) GetAlgorithm() string {
	return t.canonicalizer.GetAlgorithm()
}

func (t *c14N10RecTransform) GetReference() *Reference {
	return t.reference
}

func (t *c14N10RecTransform) TransformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error) {
	elementNsContext, err := rhtree.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	detachtedElement, err := rhtree.NSDetatch(elementNsContext, el)
	if err != nil {
		return nil, err
	}

	return t.canonicalizer.Canonicalize(ctx, detachtedElement)
}

func (t *c14N10RecTransform) TransformData(ctx context.Context, data []byte) ([]byte, error) {
	return nil, errors.New("exclusive c14n transform cannot be applied to data")
}

func (t *c14N10RecTransform) LoadXml(el *etree.Element) error {
	if el == nil {
		return errors.New("element cannot be nil")
	}
	if el.Tag != "Transform" || el.NamespaceURI() != XmlDSigNamespaceUri {
		return errors.New("element is not a transform element")
	}
	t.canonicalizer.LoadXml(el)

	return nil
}

func (t *c14N10RecTransform) GetXml() (*etree.Element, error) {
	return t.canonicalizer.GetXml()
}
