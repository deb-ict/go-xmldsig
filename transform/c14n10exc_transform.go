package transform

import (
	"context"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xmldsig/canonicalizer"
	rhtree "github.com/russellhaering/goxmldsig/etreeutils"
)

type c14N10ExcTransform struct {
	canonicalizer canonicalizer.Canonicalizer
}

func NewC14N10ExcTransform() Transform {
	return &c14N10ExcTransform{
		canonicalizer: canonicalizer.NewC14N10ExcCanonicalizer(),
	}
}

func NewC14N10ExcWithCommentsTransform() Transform {
	return &c14N10ExcTransform{
		canonicalizer: canonicalizer.NewC14N10ExcWithCommentsCanonicalizer(),
	}
}

func (t *c14N10ExcTransform) GetAlgorithm() string {
	return t.canonicalizer.GetAlgorithm()
}

func (t *c14N10ExcTransform) TransformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error) {
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

func (t *c14N10ExcTransform) TransformData(ctx context.Context, data []byte) ([]byte, error) {
	return nil, errors.New("exclusive c14n transform cannot be applied to data")
}

func (t *c14N10ExcTransform) ReadXml(el *etree.Element) error {
	t.canonicalizer.ReadXml(el)

	return nil
}

func (t *c14N10ExcTransform) WriteXml(el *etree.Element) error {
	return t.canonicalizer.WriteXml(el)
}
