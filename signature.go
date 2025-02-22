package xmldsig

import (
	"encoding/base64"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type Signature struct {
	XMLName        xml.Name        `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	Attrs          []*xml.Attr     `xml:",any,attr"`
	Id             string          `xml:"Id,attr,omitempty"`
	SignedInfo     *SignedInfo     `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	SignatureValue *SignatureValue `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	//KeyInfo        *KeyInfo        `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo,omitempty"`
	//Object         []*Object       `xml:"http://www.w3.org/2000/09/xmldsig# Object,omitempty"`
	signedXml *SignedXml
	cachedXml *etree.Element
	//signatureValue []byte
}

func newSignature(signedXml *SignedXml) *Signature {
	return &Signature{
		signedXml: signedXml,
	}
}

func (sig *Signature) root() *SignedXml {
	return sig.signedXml
}

func (sig *Signature) loadXml(el *etree.Element) error {
	if el == nil {
		return errors.New("element cannot be nil")
	}
	if el.Tag != "Signature" || el.NamespaceURI() != XmlDSigNamespaceUri {
		return errors.New("element is not a signature element")
	}

	// Get the signed info
	signedInfoElements := el.SelectElements("SignedInfo")
	if len(signedInfoElements) != 1 {
		return errors.New("element does not contain a single SignedInfo element")
	}
	sig.SignedInfo = newSignedInfo(sig)
	err := sig.SignedInfo.loadXml(signedInfoElements[0])
	if err != nil {
		return err
	}

	// Get the signature value
	signatureValueElements := el.SelectElements("SignatureValue")
	if len(signatureValueElements) != 1 {
		return errors.New("element does not contain a single SignatureValue element")
	}
	signatureValue, err := base64.StdEncoding.DecodeString(signatureValueElements[0].Text())
	if err != nil {
		return err
	}
	sig.signatureValue = signatureValue

	// Get the optional key info
	//TODO: keyInfoElements := el.SelectElements("KeyInfo[namespace-uri()='" + XmlDSigNamespaceUri + "']")

	sig.cachedXml = el
	return nil
}
