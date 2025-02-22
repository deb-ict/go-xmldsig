package xmldsig

import (
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
}

func newSignature(signedXml *SignedXml) *Signature {
	return &Signature{
		signedXml: signedXml,
	}
}

func (xml *Signature) root() *SignedXml {
	return xml.signedXml
}

func (xml *Signature) loadXml(el *etree.Element) error {
	err := validateElement(el, "Signature", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	// Get the attributes
	xml.Id = el.SelectAttrValue("Id", "")

	// Get the signed info
	signedInfoElement, err := getSingleChildElement(el, "SignedInfo", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	xml.SignedInfo = newSignedInfo(xml)
	err = xml.SignedInfo.loadXml(signedInfoElement)
	if err != nil {
		return err
	}

	// Get the signature value
	signatureValueElement, err := getSingleChildElement(el, "SignatureValue", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	xml.SignatureValue = newSignatureValue(xml)
	err = xml.SignatureValue.loadXml(signatureValueElement)
	if err != nil {
		return err
	}

	// Get the key info
	//TODO: keyInfoElements := el.SelectElements("KeyInfo[namespace-uri()='" + XmlDSigNamespaceUri + "']")

	xml.cachedXml = el
	return nil
}

func (xml *Signature) getXml() (*etree.Element, error) {
	el := etree.NewElement("Signature")
	el.Space = xml.root().getElementSpace(XmlDSigNamespaceUri)

	if xml.Id != "" {
		el.CreateAttr("Id", xml.Id)
	}

	// Add the signed info
	signedInfoEl, err := xml.SignedInfo.getXml()
	if err != nil {
		return nil, err
	}
	el.AddChild(signedInfoEl)

	// Add the signature value
	signatureValueEl, err := xml.SignatureValue.getXml()
	if err != nil {
		return nil, err
	}
	el.AddChild(signatureValueEl)

	// Add the key info
	//TODO: KeyInfo

	return el, nil
}
