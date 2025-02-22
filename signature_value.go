package xmldsig

import (
	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type SignatureValue struct {
	XMLName   xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	Attrs     []*xml.Attr `xml:",any,attr"`
	Id        string      `xml:"Id,attr,omitempty"`
	Value     string      `xml:",chardata"`
	signature *Signature
	cachedXml *etree.Element
}

func newSignatureValue(signature *Signature) *SignatureValue {
	return &SignatureValue{
		signature: signature,
	}
}

func (xml *SignatureValue) root() *SignedXml {
	return xml.signature.root()
}

func (xml *SignatureValue) loadXml(el *etree.Element) error {
	err := validateElement(el, "SignatureValue", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.Id = el.SelectAttrValue("Id", "")
	xml.Value = el.Text()

	xml.cachedXml = el
	return nil
}

func (xml *SignatureValue) getXml() (*etree.Element, error) {
	el := etree.NewElement("SignatureValue")
	el.Space = xml.root().getElementSpace(XmlDSigNamespaceUri)

	if xml.Id != "" {
		el.CreateAttr("Id", xml.Id)
	}
	el.SetText(xml.Value)

	return el, nil
}
