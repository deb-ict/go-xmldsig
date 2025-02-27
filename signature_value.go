package xmldsig

import (
	"github.com/beevik/etree"
)

type SignatureValue struct {
	Id    string
	Value string
}

func (xml *SignatureValue) LoadXml(resolver XmlResolver, el *etree.Element) error {
	err := validateElement(el, "SignatureValue", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.Id = el.SelectAttrValue("Id", "")
	xml.Value = el.Text()

	return nil
}

func (xml *SignatureValue) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("SignatureValue")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	if xml.Id != "" {
		el.CreateAttr("Id", xml.Id)
	}
	el.SetText(xml.Value)

	return el, nil
}
