package xmldsig

import (
	"context"
	"errors"

	"github.com/beevik/etree"
	rhdsig "github.com/russellhaering/goxmldsig"
)

const (
	EnvelopedSignatureTransform string = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

type envelopedSignatureTransform struct {
	reference *Reference
}

func NewEnvelopedSignatureTransform(reference *Reference) TransformMethod {
	return &envelopedSignatureTransform{
		reference: reference,
	}
}

func (t *envelopedSignatureTransform) GetAlgorithm() string {
	return EnvelopedSignatureTransform
}

func (t *envelopedSignatureTransform) GetReference() *Reference {
	return t.reference
}

func (t *envelopedSignatureTransform) TransformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error) {
	signaturePath := t.mapPathToElement(el, t.reference.signedInfo.signature.cachedXml)

	el = el.Copy()
	if !t.removeElementAtPath(el, signaturePath) {
		return nil, errors.New("Error applying canonicalization transform: Signature not found")
	}

	canonicalizer := rhdsig.MakeNullCanonicalizer()
	return canonicalizer.Canonicalize(el)
}

func (t *envelopedSignatureTransform) TransformData(ctx context.Context, data []byte) ([]byte, error) {
	return nil, errors.New("enveloped signature transform cannot be applied to data")
}

func (t *envelopedSignatureTransform) ReadXml(el *etree.Element) error {
	return nil
}

func (t *envelopedSignatureTransform) WriteXml(el *etree.Element) error {
	return nil
}

func (t *envelopedSignatureTransform) mapPathToElement(tree, el *etree.Element) []int {
	for i, child := range tree.Child {
		if child == el {
			return []int{i}
		}
	}

	for i, child := range tree.Child {
		if childElement, ok := child.(*etree.Element); ok {
			childPath := t.mapPathToElement(childElement, el)
			if childPath != nil {
				return append([]int{i}, childPath...)
			}
		}
	}

	return nil
}

func (t *envelopedSignatureTransform) removeElementAtPath(el *etree.Element, path []int) bool {
	if len(path) == 0 {
		return false
	}

	if len(el.Child) <= path[0] {
		return false
	}

	childElement, ok := el.Child[path[0]].(*etree.Element)
	if !ok {
		return false
	}

	if len(path) == 1 {
		el.RemoveChild(childElement)
		return true
	}

	return t.removeElementAtPath(childElement, path[1:])
}
