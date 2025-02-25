package xmldsig

import (
	"github.com/beevik/etree"
)

type DigestMethod struct {
	Algorithm string
	reference *Reference
	cachedXml *etree.Element
}

func newDigestMethod(reference *Reference) *DigestMethod {
	return &DigestMethod{
		reference: reference,
	}
}

func (xml *DigestMethod) root() *SignedXml {
	return xml.reference.root()
}

func (xml *DigestMethod) loadXml(el *etree.Element) error {
	err := validateElement(el, "DigestMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.Algorithm = el.SelectAttrValue("Algorithm", "")

	xml.cachedXml = el
	return nil
}

func (xml *DigestMethod) getXml() (*etree.Element, error) {
	el := etree.NewElement("DigestMethod")
	el.Space = xml.root().getElementSpace(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", xml.Algorithm)

	return el, nil
}
