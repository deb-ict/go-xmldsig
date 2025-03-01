package xmldsig

import (
	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type DigestMethod struct {
	Algorithm string
}

func (node *DigestMethod) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "DigestMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	node.Algorithm = el.SelectAttrValue("Algorithm", "")

	return nil
}

func (node *DigestMethod) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("DigestMethod")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", node.Algorithm)

	return el, nil
}
