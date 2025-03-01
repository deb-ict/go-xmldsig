package xmldsig

import (
	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type SignatureValue struct {
	Id    string
	Value string
}

func (node *SignatureValue) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "SignatureValue", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	node.Id = el.SelectAttrValue("Id", "")
	node.Value = el.Text()

	return nil
}

func (node *SignatureValue) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("SignatureValue")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	if node.Id != "" {
		el.CreateAttr("Id", node.Id)
	}
	el.SetText(node.Value)

	return el, nil
}
