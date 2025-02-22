package xmldsig

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
	rhtree "github.com/russellhaering/goxmldsig/etreeutils"
)

type SignedInfo struct {
	XMLName                xml.Name                `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	Attrs                  []*xml.Attr             `xml:",any,attr"`
	Id                     string                  `xml:"Id,attr,omitempty"`
	CanonicalizationMethod *CanonicalizationMethod `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	SignatureMethod        *SignatureMethod        `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Reference              []*Reference            `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	signature              *Signature
	cachedXml              *etree.Element
	//TODO: Replace with above
	canonicalizer Canonicalizer
	references    []*Reference
}

func newSignedInfo(signature *Signature) *SignedInfo {
	return &SignedInfo{
		signature: signature,
	}
}

func (xml *SignedInfo) root() *SignedXml {
	return xml.signature.root()
}

func (xml *SignedInfo) validateDigests(ctx context.Context) ([]*etree.Element, error) {
	validated := make([]*etree.Element, 0)
	for _, reference := range xml.references {
		err := reference.validateDigest(ctx)
		if err != nil {
			return nil, err
		}
		validated = append(validated, reference.cachedXml)
	}
	return validated, nil
}

func (xml *SignedInfo) validateSignature(ctx context.Context, cert *x509.Certificate) error {
	elementNsContext, err := rhtree.NSBuildParentContext(xml.cachedXml)
	if err != nil {
		return err
	}
	detachtedElement, err := rhtree.NSDetatch(elementNsContext, xml.cachedXml)
	if err != nil {
		return err
	}

	canonicalizedData, err := xml.canonicalizer.Canonicalize(ctx, detachtedElement)
	if err != nil {
		return err
	}

	signatureAlgorithm, err := xml.SignatureMethod.GetSignatureAlgorithm()
	if err != nil {
		return err
	}

	signatureValue, err := base64.StdEncoding.DecodeString(xml.signature.SignatureValue.Value)
	if err != nil {
		return err
	}
	err = cert.CheckSignature(signatureAlgorithm, canonicalizedData, signatureValue)
	if err != nil {
		return err
	}

	return nil
}

func (xml *SignedInfo) loadXml(el *etree.Element) error {
	err := validateElement(el, "SignedInfo", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	// Get the canonicalization method
	canonicalizationMethodElement, err := getSingleChildElement(el, "CanonicalizationMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	canonicalizationMethod := canonicalizationMethodElements[0].SelectAttrValue("Algorithm", "")
	canonicalizer, err := GetCanonicalizer(canonicalizationMethod, canonicalizationMethodElements[0])
	if err != nil {
		return err
	}
	xml.canonicalizer = canonicalizer

	// Get the signature method
	signatureMethodElement, err := getSingleChildElement(el, "SignatureMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	signatureMethodAlgorithm := signatureMethodElements[0].SelectAttrValue("Algorithm", "")
	signatureMethod, err := GetSignatureMethod(signatureMethodAlgorithm)
	if err != nil {
		return err
	}
	xml.signatureMethod = signatureMethod

	// Get the references
	referenceElements := el.SelectElements("Reference")
	for _, referenceElement := range referenceElements {
		reference := newReference(xml)
		err := reference.loadXml(referenceElement)
		if err != nil {
			return err
		}
		xml.references = append(xml.references, reference)
	}

	xml.cachedXml = el
	return nil
}

func (xml *SignedInfo) getXml() (*etree.Element, error) {
	return nil, errors.New("not implemented")
}
