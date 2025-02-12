package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
)

type CreateTransformMethod func(reference *Reference) Transform

type Transform interface {
	TransformXmlElement(el *etree.Element) ([]byte, error)
	TransformData(data []byte) ([]byte, error)
	GetAlgorithm() string
	Reference() *Reference
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
