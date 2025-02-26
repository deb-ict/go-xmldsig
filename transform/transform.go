package transform

import (
	"context"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xmldsig/canonicalizer"
)

type CreateTransform func() Transform

const (
	EnvelopedSignatureTransform string = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

var (
	registeredTransforms map[string]CreateTransform = map[string]CreateTransform{
		EnvelopedSignatureTransform:                     NewEnvelopedSignatureTransform,
		canonicalizer.C14N10RecNamespaceUri:             NewC14N10RecTransform,
		canonicalizer.C14N10RecWithCommentsNamespaceUri: NewC14N10RecWithCommentsTransform,
		canonicalizer.C14N10ExcNamespaceUri:             NewC14N10ExcTransform,
		canonicalizer.C14N10ExcWithCommentsNamespaceUri: NewC14N10ExcWithCommentsTransform,
		canonicalizer.C14N11NamespaceUri:                NewC14N11Transform,
		canonicalizer.C14N11WithCommentsNamespaceUri:    NewC14N11WithCommentsTransform,
	}
)

type Transform interface {
	GetAlgorithm() string
	TransformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error)
	TransformData(ctx context.Context, data []byte) ([]byte, error)
	ReadXml(el *etree.Element) error
	WriteXml(el *etree.Element) error
}

func RegisterTransform(uri string, method CreateTransform) {
	registeredTransforms[uri] = method
}

func GetTransform(uri string) (Transform, error) {
	if method, ok := registeredTransforms[uri]; ok {
		return method(), nil
	}
	return nil, errors.New("transform not found")
}
