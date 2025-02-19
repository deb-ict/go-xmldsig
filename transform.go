package xmldsig

import (
	"context"
	"errors"

	"github.com/beevik/etree"
)

type CreateTransformMethod func(reference *Reference) Transform

type Transform interface {
	GetAlgorithm() string
	GetReference() *Reference
	TransformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error)
	TransformData(ctx context.Context, data []byte) ([]byte, error)
	LoadXml(el *etree.Element) error
}

func RegisterTransform(uri string, method CreateTransformMethod) {
	registeredTransforms[uri] = method
}

func GetTransform(uri string, ref *Reference) (Transform, error) {
	if method, ok := registeredTransforms[uri]; ok {
		return method(ref), nil
	}
	return nil, errors.New("transform not found")
}
