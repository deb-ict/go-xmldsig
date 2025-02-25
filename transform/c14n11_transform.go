package transform

import (
	"context"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xmldsig/canonicalizer"
	rhtree "github.com/russellhaering/goxmldsig/etreeutils"
)

type c14N11Transform struct {
	canonicalizer canonicalizer.Canonicalizer
}

func NewC14N11Transform() TransformMethod {
	return &c14N11Transform{
		canonicalizer: canonicalizer.NewC14N11Canonicalizer(),
	}
}

func NewC14N11WithCommentsTransform() TransformMethod {
	return &c14N11Transform{
		canonicalizer: canonicalizer.NewC14N11WithCommentsCanonicalizer(),
	}
}

func (t *c14N11Transform) GetAlgorithm() string {
	return t.canonicalizer.GetAlgorithm()
}

func (t *c14N11Transform) TransformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error) {
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

func (t *c14N11Transform) TransformData(ctx context.Context, data []byte) ([]byte, error) {
	return nil, errors.New("exclusive c14n transform cannot be applied to data")
}

func (t *c14N11Transform) ReadXml(el *etree.Element) error {
	t.canonicalizer.ReadXml(el)

	return nil
}

func (t *c14N11Transform) WriteXml(el *etree.Element) error {
	return t.canonicalizer.WriteXml(el)
}
