package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
)

const (
	XmlDSigNamespaceUri string = "http://www.w3.org/2000/09/xmldsig#"
)

var (
	ErrElementIsNil           = errors.New("element is nil")
	ErrInvalidElementTag      = errors.New("invalid element tag")
	ErrInvalidSignatureMethod = errors.New("invalid signature method")
	ErrInvalidDigestMethod    = errors.New("invalid digest method")
)

var (
	registeredCanonicalizers map[string]CreateCanonicalizerMethod = map[string]CreateCanonicalizerMethod{
		C14N10RecNamespaceUri:             NewC14N10RecCanonicalizer,
		C14N10RecWithCommentsNamespaceUri: NewC14N10RecWithCommentsCanonicalizer,
		C14N10ExcNamespaceUri:             NewC14N10ExcCanonicalizer,
		C14N10ExcWithCommentsNamespaceUri: NewC14N10ExcWithCommentsCanonicalizer,
		C14N11NamespaceUri:                NewC14N11Canonicalizer,
		C14N11WithCommentsNamespaceUri:    NewC14N11WithCommentsCanonicalizer,
	}
	registeredTransforms map[string]CreateTransformMethod = map[string]CreateTransformMethod{
		EnvelopedSignatureTransform:       NewEnvelopedSignatureTransform,
		C14N10RecNamespaceUri:             NewC14N10RecTransform,
		C14N10RecWithCommentsNamespaceUri: NewC14N10RecWithCommentsTransform,
		C14N10ExcNamespaceUri:             NewC14N10ExcTransform,
		C14N10ExcWithCommentsNamespaceUri: NewC14N10ExcWithCommentsTransform,
		C14N11NamespaceUri:                NewC14N11Transform,
		C14N11WithCommentsNamespaceUri:    NewC14N11WithCommentsTransform,
	}
	referenceElementResolvers map[string]ResolveReferenceMethod = map[string]ResolveReferenceMethod{}
)

func CryptographicEquals(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	r := 0
	for i := range a {
		r |= (int(a[i]) - int(b[i]))
	}
	return (r == 0)
}

func validateElement(el *etree.Element, tag string, namespaceUri string) error {
	if el == nil {
		return ErrElementIsNil
	}
	if el.Tag != tag || el.NamespaceURI() != namespaceUri {
		return ErrInvalidElementTag
	}
	return nil
}

func getSingleChildElement(el *etree.Element, tag string, namespaceUri string) (*etree.Element, error) {
	elements := el.SelectElements(tag)
	if len(elements) == 0 {
		return nil, newChildElementNotFoundError(el, tag, namespaceUri)
	}
	if len(elements) > 1 {
		return nil, NewMultipleChildElementsFoundError(el, tag, namespaceUri)
	}
	return elements[0], nil
}

func getOptionalSingleChildElement(el *etree.Element, tag string, namespaceUri string) (*etree.Element, error) {
	elements := el.SelectElements(tag)
	if len(elements) > 1 {
		return nil, NewMultipleChildElementsFoundError(el, tag, namespaceUri)
	}
	if len(elements) > 0 {
		return elements[0], nil
	}
	return nil, nil
}
