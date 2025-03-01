package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type Signature struct {
	Id             string
	SignedInfo     *SignedInfo
	SignatureValue *SignatureValue
	KeyInfo        *KeyInfo
	cachedXml      *etree.Element
}

func (node *Signature) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "Signature", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	// Get the attributes
	node.Id = el.SelectAttrValue("Id", "")

	// Get the signed info
	signedInfoElement, err := getSingleChildElement(el, "SignedInfo", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	node.SignedInfo = &SignedInfo{}
	err = node.SignedInfo.LoadXml(resolver, signedInfoElement)
	if err != nil {
		return err
	}

	// Get the signature value
	signatureValueElement, err := getSingleChildElement(el, "SignatureValue", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	node.SignatureValue = &SignatureValue{}
	err = node.SignatureValue.LoadXml(resolver, signatureValueElement)
	if err != nil {
		return err
	}

	// Get the key info
	keyInfoElement, err := getSingleChildElement(el, "KeyInfo", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	node.KeyInfo = &KeyInfo{}
	err = node.KeyInfo.LoadXml(resolver, keyInfoElement)
	if err != nil {
		return err
	}

	node.cachedXml = el
	return nil
}

func (node *Signature) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("Signature")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	if node.Id != "" {
		el.CreateAttr("Id", node.Id)
	}

	// Add the signed info
	if node.SignedInfo == nil {
		return nil, errors.New("signature does not contain a SignedInfo element")
	}
	signedInfoElement, err := node.SignedInfo.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(signedInfoElement)

	// Add the signature value
	if node.SignatureValue == nil {
		return nil, errors.New("signature does not contain a SignatureValue element")
	}
	signatureValueElement, err := node.SignatureValue.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(signatureValueElement)

	// Add the key info
	if node.KeyInfo == nil {
		return nil, errors.New("signature does not contain a KeyInfo element")
	}
	keyInfoElement, err := node.KeyInfo.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(keyInfoElement)

	return el, nil
}
