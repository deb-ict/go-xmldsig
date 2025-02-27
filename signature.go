package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
)

type Signature struct {
	Id             string
	SignedInfo     *SignedInfo
	SignatureValue *SignatureValue
	KeyInfo        *KeyInfo
	cachedXml      *etree.Element
}

func (xml *Signature) LoadXml(resolver XmlResolver, el *etree.Element) error {
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
	xml.SignedInfo = &SignedInfo{}
	err = xml.SignedInfo.LoadXml(resolver, signedInfoElement)
	if err != nil {
		return err
	}

	// Get the signature value
	signatureValueElement, err := getSingleChildElement(el, "SignatureValue", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	xml.SignatureValue = &SignatureValue{}
	err = xml.SignatureValue.LoadXml(resolver, signatureValueElement)
	if err != nil {
		return err
	}

	// Get the key info
	keyInfoElement, err := getSingleChildElement(el, "KeyInfo", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	xml.KeyInfo = &KeyInfo{}
	err = xml.KeyInfo.LoadXml(resolver, keyInfoElement)
	if err != nil {
		return err
	}

	xml.cachedXml = el
	return nil
}

func (xml *Signature) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("Signature")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	if xml.Id != "" {
		el.CreateAttr("Id", xml.Id)
	}

	// Add the signed info
	if xml.SignedInfo == nil {
		return nil, errors.New("signature does not contain a SignedInfo element")
	}
	signedInfoElement, err := xml.SignedInfo.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(signedInfoElement)

	// Add the signature value
	if xml.SignatureValue == nil {
		return nil, errors.New("signature does not contain a SignatureValue element")
	}
	signatureValueElement, err := xml.SignatureValue.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(signatureValueElement)

	// Add the key info
	if xml.KeyInfo == nil {
		return nil, errors.New("signature does not contain a KeyInfo element")
	}
	keyInfoElement, err := xml.KeyInfo.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(keyInfoElement)

	return el, nil
}
