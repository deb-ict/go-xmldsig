package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
)

type Signature struct {
	Id             string
	SignedInfo     *SignedInfo
	SignatureValue *SignatureValue
	signedXml      *SignedXml
	cachedXml      *etree.Element
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
	if xml.SignedInfo == nil {
		return nil, errors.New("signature does not contain a SignedInfo element")
	}
	signedInfoElement, err := xml.SignedInfo.getXml()
	if err != nil {
		return nil, err
	}
	el.AddChild(signedInfoElement)

	// Add the signature value
	if xml.SignatureValue == nil {
		return nil, errors.New("signature does not contain a SignatureValue element")
	}
	signatureValueElement, err := xml.SignatureValue.getXml()
	if err != nil {
		return nil, err
	}
	el.AddChild(signatureValueElement)

	// Add the key info
	//TODO: KeyInfo

	return el, nil
}
