package transform

import (
	"context"
	"errors"

	"github.com/beevik/etree"
	rhdsig "github.com/russellhaering/goxmldsig"
)

type envelopedSignatureTransform struct {
}

func NewEnvelopedSignatureTransform() Transform {
	return &envelopedSignatureTransform{}
}

func (t *envelopedSignatureTransform) GetAlgorithm() string {
	return EnvelopedSignatureTransform
}

func (t *envelopedSignatureTransform) TransformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error) {
	signatureElement := el.FindElement("Signature[namespace-uri()='http://www.w3.org/2000/09/xmldsig#']")
	if signatureElement == nil {
		return nil, errors.New("Error applying canonicalization transform: Signature not found")
	}
	signaturePath := t.mapPathToElement(el, signatureElement)

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

func (t *envelopedSignatureTransform) findParentElement(el *etree.Element, tag, namespaceUri string) (*etree.Element, error) {
	if el == nil {
		return nil, errors.New("Element not found")
	}

	if el.Tag == tag && el.NamespaceURI() == namespaceUri {
		return el, nil
	}

	parent := el.Parent()
	if parent != nil {
		return t.findParentElement(parent, tag, namespaceUri)
	}

	return nil, errors.New("Element not found")
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
