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
	References             []*Reference            `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	signature              *Signature
	cachedXml              *etree.Element
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
	for _, reference := range xml.References {
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

	canonicalizedData, err := xml.CanonicalizationMethod.canonicalizer.Canonicalize(ctx, detachtedElement)
	if err != nil {
		return err
	}

	signatureMethod, err := GetSignatureMethod(xml.SignatureMethod.Algorithm)
	if err != nil {
		return err
	}
	signatureAlgorithm, err := signatureMethod.GetSignatureAlgorithm()
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
	xml.CanonicalizationMethod = newCanonicalizationMethod(xml)
	err = xml.CanonicalizationMethod.loadXml(canonicalizationMethodElement)
	if err != nil {
		return err
	}

	// Get the signature method
	signatureMethodElement, err := getSingleChildElement(el, "SignatureMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	xml.SignatureMethod = newSignatureMethod(xml)
	err = xml.SignatureMethod.loadXml(signatureMethodElement)
	if err != nil {
		return err
	}

	// Get the references
	referenceElements := el.SelectElements("Reference")
	for _, referenceElement := range referenceElements {
		reference := newReference(xml)
		err := reference.loadXml(referenceElement)
		if err != nil {
			return err
		}
		xml.References = append(xml.References, reference)
	}

	xml.cachedXml = el
	return nil
}

func (xml *SignedInfo) getXml() (*etree.Element, error) {
	el := etree.NewElement("SignedInfo")
	el.Space = xml.root().getElementSpace(XmlDSigNamespaceUri)

	if xml.Id != "" {
		el.CreateAttr("Id", xml.Id)
	}

	if xml.CanonicalizationMethod == nil {
		return nil, errors.New("signed info does not contain a CanonicalizationMethod element")
	}
	canonicalizationMethodElement, err := xml.CanonicalizationMethod.getXml()
	if err != nil {
		return nil, err
	}
	el.AddChild(canonicalizationMethodElement)

	if xml.SignatureMethod == nil {
		return nil, errors.New("signed info does not contain a SignatureMethod element")
	}
	signatureMethodElement, err := xml.SignatureMethod.getXml()
	if err != nil {
		return nil, err
	}
	el.AddChild(signatureMethodElement)

	for _, reference := range xml.References {
		referenceElement, err := reference.getXml()
		if err != nil {
			return nil, err
		}
		el.AddChild(referenceElement)
	}

	return el, nil
}
