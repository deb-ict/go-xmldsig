package xmldsig

import (
	"crypto/x509"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
	"github.com/deb-ict/go-xmlsecurity"
)

type KeyInfo struct {
	Id       string
	X509Data *X509Data
	Other    xml.XmlNode
}

func (node *KeyInfo) GetX509Certificate(resolver xml.XmlResolver) (*x509.Certificate, error) {
	if node.X509Data != nil {
		return node.X509Data.GetX509Certificate(resolver)
	}

	provider, ok := node.Other.(xmlsecurity.X509CertificateProvider)
	if !ok {
		return nil, errors.New("KeyInfo does not contain a certificate provider")
	}
	return provider.GetX509Certificate(resolver)
}

func (node *KeyInfo) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "KeyInfo", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	node.Id = el.SelectAttrValue("Id", "")

	for _, child := range el.ChildElements() {
		if child.Space == XmlDSigNamespaceUri {
			switch child.Tag {
			case "X509Data":
				err = node.loadX509Data(resolver, child)
			default:
				err = errors.New("unexpected element in KeyInfo")
			}
		} else {
			err = node.loadOther(resolver, child)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (node *KeyInfo) loadX509Data(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "X509Data", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	node.X509Data = &X509Data{}
	return node.X509Data.LoadXml(resolver, el)
}

func (node *KeyInfo) loadOther(resolver xml.XmlResolver, el *etree.Element) error {
	typeConstructor, err := resolver.GetTypeConstructor(el.Space, el.Tag)
	if err != nil {
		return err
	}
	other, err := typeConstructor(resolver)
	if err != nil {
		return err
	}
	err = other.LoadXml(resolver, el)
	if err != nil {
		return err
	}

	node.Other = other
	return nil
}

func (node *KeyInfo) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("KeyInfo")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	if node.Id != "" {
		el.CreateAttr("Id", node.Id)
	}

	if node.X509Data != nil {
		x509DataElement, err := node.X509Data.GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(x509DataElement)
	}

	if node.Other != nil {
		otherElement, err := node.Other.GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(otherElement)
	}

	return el, nil
}
