package xmldsig

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
	rhtree "github.com/russellhaering/goxmldsig/etreeutils"
)

type SignedInfo struct {
	Id                     string
	CanonicalizationMethod *CanonicalizationMethod
	SignatureMethod        *SignatureMethod
	References             []*Reference
	cachedXml              *etree.Element
}

func (node *SignedInfo) validateDigests(ctx context.Context, doc *etree.Document) ([]*etree.Element, error) {
	validated := make([]*etree.Element, 0)
	for _, reference := range node.References {
		err := reference.validateDigest(ctx, doc)
		if err != nil {
			return nil, err
		}
		validated = append(validated, reference.cachedXml)
	}
	return validated, nil
}

func (node *SignedInfo) validateSignature(ctx context.Context, cert *x509.Certificate, signatureValue []byte) error {
	elementNsContext, err := rhtree.NSBuildParentContext(node.cachedXml)
	if err != nil {
		return err
	}
	detachtedElement, err := rhtree.NSDetatch(elementNsContext, node.cachedXml)
	if err != nil {
		return err
	}

	canonicalizedData, err := node.CanonicalizationMethod.canonicalizer.Canonicalize(ctx, detachtedElement)
	if err != nil {
		return err
	}

	signatureMethod, err := GetSignatureMethod(node.SignatureMethod.Algorithm)
	if err != nil {
		return err
	}
	signatureAlgorithm, err := signatureMethod.GetSignatureAlgorithm()
	if err != nil {
		return err
	}

	err = cert.CheckSignature(signatureAlgorithm, canonicalizedData, signatureValue)
	if err != nil {
		return err
	}

	return nil
}

func (node *SignedInfo) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "SignedInfo", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	// Get the canonicalization method
	canonicalizationMethodElement, err := getSingleChildElement(el, "CanonicalizationMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	node.CanonicalizationMethod = &CanonicalizationMethod{}
	err = node.CanonicalizationMethod.LoadXml(resolver, canonicalizationMethodElement)
	if err != nil {
		return err
	}

	// Get the signature method
	signatureMethodElement, err := getSingleChildElement(el, "SignatureMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	node.SignatureMethod = &SignatureMethod{}
	err = node.SignatureMethod.LoadXml(resolver, signatureMethodElement)
	if err != nil {
		return err
	}

	// Get the references
	referenceElements := el.SelectElements("Reference")
	for _, referenceElement := range referenceElements {
		reference := &Reference{}
		err := reference.LoadXml(resolver, referenceElement)
		if err != nil {
			return err
		}
		node.References = append(node.References, reference)
	}

	node.cachedXml = el
	return nil
}

func (node *SignedInfo) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("SignedInfo")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	if node.Id != "" {
		el.CreateAttr("Id", node.Id)
	}

	if node.CanonicalizationMethod == nil {
		return nil, errors.New("signed info does not contain a CanonicalizationMethod element")
	}
	canonicalizationMethodElement, err := node.CanonicalizationMethod.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(canonicalizationMethodElement)

	if node.SignatureMethod == nil {
		return nil, errors.New("signed info does not contain a SignatureMethod element")
	}
	signatureMethodElement, err := node.SignatureMethod.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(signatureMethodElement)

	for _, reference := range node.References {
		referenceElement, err := reference.GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(referenceElement)
	}

	return el, nil
}
