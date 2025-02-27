package xmldsig

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"github.com/beevik/etree"
)

type SignedXml struct {
	document  *etree.Document
	signature *Signature
}

func LoadSignedXml(resolver XmlResolver, doc *etree.Document) (*SignedXml, error) {
	xml := &SignedXml{
		document: doc,
	}
	err := xml.LoadXml(resolver, doc)
	if err != nil {
		return nil, err
	}

	return xml, nil
}

func (xml *SignedXml) ValidateSignature(ctx context.Context, cert *x509.Certificate) ([]*etree.Element, error) {
	if xml.signature == nil || xml.signature.SignedInfo == nil {
		return nil, errors.New("signature or signed info is nil")
	}
	validated, err := xml.signature.SignedInfo.validateDigests(ctx, xml.document)
	if err != nil {
		return nil, err
	}

	signatureValue, err := base64.StdEncoding.DecodeString(xml.signature.SignatureValue.Value)
	if err != nil {
		return nil, err
	}
	err = xml.signature.SignedInfo.validateSignature(ctx, cert, signatureValue)
	if err != nil {
		return nil, err
	}

	return validated, nil
}

func (xml *SignedXml) GetCertificate() (*x509.Certificate, error) {
	if xml.signature == nil {
		return nil, errors.New("signature or signed info is nil")
	}
	if xml.signature.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}
	return xml.signature.KeyInfo.GetCertificate()

	signatureXml := xml.signature.cachedXml
	if signatureXml == nil {
		return nil, errors.New("signature xml is nil")
	}

	keyInfoElements := signatureXml.SelectElements("KeyInfo")
	if len(keyInfoElements) != 1 {
		return nil, errors.New("signature does not contain a single KeyInfo element")
	}

	x509DataElements := keyInfoElements[0].SelectElements("X509Data")
	if len(x509DataElements) > 0 {
		x509CertificateElements := x509DataElements[0].SelectElements("X509Certificate")
		if len(x509CertificateElements) != 1 {
			return nil, errors.New("signature does not contain a single X509Certificate element")
		}

		x509Data, err := base64.StdEncoding.DecodeString(x509CertificateElements[0].Text())
		if err != nil {
			return nil, err
		}
		x509Cert, err := x509.ParseCertificate(x509Data)
		if err != nil {
			return nil, err
		}

		return x509Cert, nil
	}

	tokenReferenceElements := keyInfoElements[0].SelectElements("SecurityTokenReference")
	if len(tokenReferenceElements) > 0 {
		referenceElements := tokenReferenceElements[0].SelectElements("Reference")
		if len(referenceElements) != 1 {
			return nil, errors.New("signature does not contain a single Reference element")
		}

		uri := referenceElements[0].SelectAttrValue("URI", "")
		if uri == "" {
			return nil, errors.New("signature does not contain a URI")
		}

		securityTokenElements := xml.document.FindElements("//BinarySecurityToken[@Id='" + uri[1:] + "']")
		if len(securityTokenElements) != 1 {
			return nil, errors.New("document does not contain a single BinarySecurityToken element")
		}

		x509Data, err := base64.StdEncoding.DecodeString(securityTokenElements[0].Text())
		if err != nil {
			return nil, err
		}
		x509Cert, err := x509.ParseCertificate(x509Data)
		if err != nil {
			return nil, err
		}

		return x509Cert, nil
	}

	return nil, errors.New("certificate not found")
}

func (xml *SignedXml) LoadXml(resolver XmlResolver, doc *etree.Document) error {
	// Get the signature
	signatureElements := doc.FindElements("//Signature[namespace-uri()='" + XmlDSigNamespaceUri + "']")
	if len(signatureElements) != 1 {
		return errors.New("element does not contain a single Signature element")
	}
	xml.signature = &Signature{}
	err := xml.signature.LoadXml(resolver, signatureElements[0])
	if err != nil {
		return err
	}

	return nil
}
