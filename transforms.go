package xmldsig

import (
	"context"

	"github.com/beevik/etree"
)

type Transforms struct {
	Transforms []*Transform
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

func (xml *Transforms) LoadXml(resolver XmlResolver, el *etree.Element) error {
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
		xml.Transforms = append(xml.Transforms, transform)
	}

	return nil
}

func (xml *Transforms) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("Transforms")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	for _, transform := range xml.Transforms {
		transformElement, err := transform.GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(transformElement)
	}

	return el, nil
}
