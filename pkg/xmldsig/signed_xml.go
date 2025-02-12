package xmldsig

import (
	"crypto/x509"
	"errors"

	"github.com/beevik/etree"
)

type SignedXml struct {
	document  *etree.Document
	signature *Signature
}

func LoadSignedXml(doc *etree.Document) (*SignedXml, error) {
	xml := &SignedXml{
		document: doc,
	}
	err := xml.loadXml(doc)
	if err != nil {
		return nil, err
	}

	return xml, nil
}

func (xml *SignedXml) ValidateSignature(cert *x509.Certificate) error {
	if xml.signature == nil || xml.signature.signedInfo == nil {
		return errors.New("signature or signed info is nil")
	}
	err := xml.signature.signedInfo.validateDigests()
	if err != nil {
		return err
	}

	err = xml.signature.signedInfo.validateSignature(cert)
	if err != nil {
		return err
	}

	return nil
}

func (xml *SignedXml) loadXml(doc *etree.Document) error {
	// Get the signature
	signatureElements := doc.FindElements("//Signature[namespace-uri()='" + XmlDSigNamespaceUri + "']")
	if len(signatureElements) != 1 {
		return errors.New("element does not contain a single Signature element")
	}
	xml.signature = newSignature(xml)
	err := xml.signature.loadXml(signatureElements[0])
	if err != nil {
		return err
	}

	return nil
}
