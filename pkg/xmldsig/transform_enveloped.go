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
	signaturePath := t.mapPathToElement(el, t.reference.signedInfo.signature.cachedXml)
	if !t.removeElementAtPath(el, signaturePath) {
		return nil, errors.New("Error applying canonicalization transform: Signature not found")
	}
}

func (t *envelopedSignatureTransform) TransformData(data []byte) ([]byte, error) {
	return nil, errors.New("enveloped signature transform cannot be applied to data")
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

func NewEnvelopedSignatureTransform(reference *Reference) Transform {
	return &envelopedSignatureTransform{
		reference: reference,
	}
}
