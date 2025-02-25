package xmldsig

import (
	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type CanonicalizationMethod struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Attrs      []*xml.Attr `xml:",any,attr"`
	Algorithm  string      `xml:"Algorithm,attr"`
	Content    []any       `xml:",any"`
	signedInfo *SignedInfo
	cachedXml  *etree.Element
}

func newCanonicalizationMethod(signedInfo *SignedInfo) *CanonicalizationMethod {
	return &CanonicalizationMethod{
		signedInfo: signedInfo,
	}
}

func (xml *CanonicalizationMethod) root() *SignedXml {
	return xml.signedInfo.root()
}

func (xml *CanonicalizationMethod) loadXml(el *etree.Element) error {
	err := validateElement(el, "CanonicalizationMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.Algorithm = el.SelectAttrValue("Algorithm", "")

	xml.cachedXml = el
	return nil
}

func (xml *CanonicalizationMethod) getXml() (*etree.Element, error) {
	el := etree.NewElement("CanonicalizationMethod")
	el.Space = xml.root().getElementSpace(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", xml.Algorithm)

	return el, nil
}
