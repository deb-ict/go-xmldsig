package xmldsig

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
	"github.com/deb-ict/go-xmlsecurity"
)

type SignedXml struct {
	document  *etree.Document
	signature *Signature
}

func LoadSignedXml(resolver xml.XmlResolver, doc *etree.Document) (*SignedXml, error) {
	xmlsecurity.ConfigureResolver(resolver)

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

func (xml *SignedXml) GetCertificate(resolver xml.XmlResolver) (*x509.Certificate, error) {
	if xml.signature == nil {
		return nil, errors.New("signature or signed info is nil")
	}
	if xml.signature.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}
	return xml.signature.KeyInfo.GetX509Certificate(resolver)
}

func (xml *SignedXml) LoadXml(resolver xml.XmlResolver, doc *etree.Document) error {
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
