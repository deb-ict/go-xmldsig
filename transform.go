package xmldsig

import (
	"context"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xmldsig/transform"
)

type Transform struct {
	Algorithm string
	XPath     string
	Transform transform.Transform
}

func (xml *Transform) transformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error) {
	err := xml.ensureTransform()
	if err != nil {
		return nil, err
	}
	return xml.Transform.TransformXmlElement(ctx, el)
}

func (xml *Transform) transformData(ctx context.Context, data []byte) ([]byte, error) {
	err := xml.ensureTransform()
	if err != nil {
		return nil, err
	}
	return xml.Transform.TransformData(ctx, data)
}

func (xml *Transform) LoadXml(resolver XmlResolver, el *etree.Element) error {
	err := validateElement(el, "Transform", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.Algorithm = el.SelectAttrValue("Algorithm", "")

	xpathElement, err := getOptionalSingleChildElement(el, "XPath", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	if xpathElement != nil {
		xml.XPath = xpathElement.Text()
	}

	err = xml.ensureTransform()
	if err != nil {
		return err
	}
	err = xml.Transform.ReadXml(el)
	if err != nil {
		return err
	}

	return nil
}

func (xml *Transform) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("Transform")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", xml.Algorithm)

	if xml.XPath != "" {
		xpathEl := el.CreateElement("XPath")
		xpathEl.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)
		xpathEl.SetText(xml.XPath)
	}

	err := xml.ensureTransform()
	if err != nil {
		return nil, err
	}
	err = xml.Transform.WriteXml(el)
	if err != nil {
		return nil, err
	}

	return el, nil
}

func (xml *Transform) ensureTransform() error {
	if xml.Transform == nil {
		Transform, err := transform.GetTransform(xml.Algorithm)
		if err != nil {
			return err
		}
		xml.Transform = Transform
	}
	return nil
}
