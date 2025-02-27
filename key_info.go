package xmldsig

import (
	"crypto/x509"
	"errors"

	"github.com/beevik/etree"
)

type KeyInfo struct {
	Id       string
	X509Data *X509Data
	Other    XmlNode
}

func (xml *KeyInfo) GetCertificate() (*x509.Certificate, error) {
	if xml.X509Data != nil {
		return xml.X509Data.GetCertificate()
	}

	provider, ok := xml.Other.(CertificateProvider)
	if !ok {
		return nil, errors.New("KeyInfo does not contain a certificate provider")
	}
	return provider.GetCertificate()
}

func (xml *KeyInfo) LoadXml(resolver XmlResolver, el *etree.Element) error {
	err := validateElement(el, "KeyInfo", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.Id = el.SelectAttrValue("Id", "")

	for _, child := range el.ChildElements() {
		if child.Space == XmlDSigNamespaceUri {
			switch child.Tag {
			case "X509Data":
				xml.X509Data = &X509Data{}
				err = xml.X509Data.LoadXml(resolver, child)
				if err != nil {
					return err
				}
			default:
				return errors.New("unexpected element in KeyInfo")
			}
		} else {
			typeConstructor, err := resolver.GetTypeConstructor(child.Space, child.Tag)
			if err != nil {
				return err
			}
			other, err := typeConstructor(resolver)
			if err != nil {
				return err
			}
			err = other.LoadXml(resolver, child)
			if err != nil {
				return err
			}
			xml.Other = other
		}
	}

	return nil
}

func (xml *KeyInfo) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("KeyInfo")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	if xml.Id != "" {
		el.CreateAttr("Id", xml.Id)
	}

	if xml.X509Data != nil {
		x509DataElement, err := xml.X509Data.GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(x509DataElement)
	}

	if xml.Other != nil {
		otherElement, err := xml.Other.GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(otherElement)
	}

	return el, nil
}
