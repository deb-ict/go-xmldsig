package xmldsig

import (
	"context"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type Transforms struct {
	XMLName    xml.Name     `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Attrs      []*xml.Attr  `xml:",any,attr"`
	Transforms []*Transform `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
	reference  *Reference
	cachedXml  *etree.Element
}

func newTransforms(reference *Reference) *Transforms {
	return &Transforms{
		reference: reference,
	}
}

func (xml *Transforms) transformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error) {
	var data []byte
	var err error
	for _, transform := range xml.Transforms {
		if data == nil {
			data, err = transform.transformXmlElement(ctx, el)
		} else {
			data, err = transform.transformData(ctx, data)
		}
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (xml *Transforms) transformData(ctx context.Context, data []byte) ([]byte, error) {
	var err error
	for _, transform := range xml.Transforms {
		data, err = transform.transformData(ctx, data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (xml *Transforms) root() *SignedXml {
	return xml.reference.root()
}

func (xml *Transforms) loadXml(el *etree.Element) error {
	err := validateElement(el, "Transforms", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	transformElements := el.SelectElements("Transform")
	for _, transformElement := range transformElements {
		transform := newTransform(xml)
		err := transform.loadXml(transformElement)
		if err != nil {
			return err
		}
		xml.Transforms = append(xml.Transforms, transform)
	}

	xml.cachedXml = el
	return nil
}

func (xml *Transforms) getXml() (*etree.Element, error) {
	el := etree.NewElement("Transforms")
	el.Space = xml.root().getElementSpace(XmlDSigNamespaceUri)

	for _, transform := range xml.Transforms {
		transformElement, err := transform.getXml()
		if err != nil {
			return nil, err
		}
		el.AddChild(transformElement)
	}

	return el, nil
}
