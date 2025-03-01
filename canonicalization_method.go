package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
	"github.com/deb-ict/go-xmldsig/canonicalizer"
)

type CanonicalizationMethod struct {
	Algorithm     string
	canonicalizer canonicalizer.Canonicalizer
}

func (node *CanonicalizationMethod) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "CanonicalizationMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	node.Algorithm = el.SelectAttrValue("Algorithm", "")

	canonicalizer, err := canonicalizer.LoadCanonicalizer(node.Algorithm, el)
	if err != nil {
		return err
	}
	node.canonicalizer = canonicalizer

	return nil
}

func (node *CanonicalizationMethod) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("CanonicalizationMethod")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", node.Algorithm)

	if node.canonicalizer == nil {
		return nil, errors.New("canonicalizer is nil")
	}
	err := node.canonicalizer.WriteXml(el)
	if err != nil {
		return nil, err
	}

	return el, nil
}
