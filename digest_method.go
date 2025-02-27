package xmldsig

import (
	"github.com/beevik/etree"
)

type DigestMethod struct {
	Algorithm string
}

func (xml *DigestMethod) LoadXml(resolver XmlResolver, el *etree.Element) error {
	err := validateElement(el, "DigestMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.Algorithm = el.SelectAttrValue("Algorithm", "")

	return nil
}

func (xml *DigestMethod) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("DigestMethod")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", xml.Algorithm)

	return el, nil
}
