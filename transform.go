package xmldsig

import (
	"context"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
	"github.com/deb-ict/go-xmldsig/transform"
)

type Transform struct {
	Algorithm string
	XPath     string
	Transform transform.Transform
}

func (node *Transform) transformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error) {
	err := node.ensureTransform()
	if err != nil {
		return nil, err
	}
	return node.Transform.TransformXmlElement(ctx, el)
}

func (node *Transform) transformData(ctx context.Context, data []byte) ([]byte, error) {
	err := node.ensureTransform()
	if err != nil {
		return nil, err
	}
	return node.Transform.TransformData(ctx, data)
}

func (node *Transform) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "Transform", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	node.Algorithm = el.SelectAttrValue("Algorithm", "")

	xpathElement, err := getOptionalSingleChildElement(el, "XPath", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	if xpathElement != nil {
		node.XPath = xpathElement.Text()
	}

	err = node.ensureTransform()
	if err != nil {
		return err
	}
	err = node.Transform.ReadXml(el)
	if err != nil {
		return err
	}

	return nil
}

func (node *Transform) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("Transform")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", node.Algorithm)

	if node.XPath != "" {
		xpathEl := el.CreateElement("XPath")
		xpathEl.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)
		xpathEl.SetText(node.XPath)
	}

	err := node.ensureTransform()
	if err != nil {
		return nil, err
	}
	err = node.Transform.WriteXml(el)
	if err != nil {
		return nil, err
	}

	return el, nil
}

func (node *Transform) ensureTransform() error {
	if node.Transform == nil {
		Transform, err := transform.GetTransform(node.Algorithm)
		if err != nil {
			return err
		}
		node.Transform = Transform
	}
	return nil
}
