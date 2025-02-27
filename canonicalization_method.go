package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xmldsig/canonicalizer"
)

type CanonicalizationMethod struct {
	Algorithm     string
	canonicalizer canonicalizer.Canonicalizer
}

func (xml *CanonicalizationMethod) LoadXml(resolver XmlResolver, el *etree.Element) error {
	err := validateElement(el, "CanonicalizationMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.Algorithm = el.SelectAttrValue("Algorithm", "")

	canonicalizer, err := canonicalizer.LoadCanonicalizer(xml.Algorithm, el)
	if err != nil {
		return err
	}
	xml.canonicalizer = canonicalizer

	return nil
}

func (xml *CanonicalizationMethod) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("CanonicalizationMethod")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", xml.Algorithm)

	if xml.canonicalizer == nil {
		return nil, errors.New("canonicalizer is nil")
	}
	err := xml.canonicalizer.WriteXml(el)
	if err != nil {
		return nil, err
	}

	return el, nil
}
