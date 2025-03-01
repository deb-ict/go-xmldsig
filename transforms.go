package xmldsig

import (
	"context"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type Transforms struct {
	Transforms []*Transform
}

func (node *Transforms) transformXmlElement(ctx context.Context, el *etree.Element) ([]byte, error) {
	var data []byte
	var err error
	for _, transform := range node.Transforms {
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

func (node *Transforms) transformData(ctx context.Context, data []byte) ([]byte, error) {
	var err error
	for _, transform := range node.Transforms {
		data, err = transform.transformData(ctx, data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (node *Transforms) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "Transforms", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	transformElements := el.SelectElements("Transform")
	for _, transformElement := range transformElements {
		transform := &Transform{}
		err := transform.LoadXml(resolver, transformElement)
		if err != nil {
			return err
		}
		node.Transforms = append(node.Transforms, transform)
	}

	return nil
}

func (node *Transforms) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("Transforms")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	for _, transform := range node.Transforms {
		transformElement, err := transform.GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(transformElement)
	}

	return el, nil
}
