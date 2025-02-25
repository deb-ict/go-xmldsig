package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xmldsig/canonicalizer"
)

type CanonicalizationMethod struct {
	Algorithm     string
	signedInfo    *SignedInfo
	cachedXml     *etree.Element
	canonicalizer canonicalizer.Canonicalizer
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

	canonicalizer, err := canonicalizer.LoadCanonicalizer(xml.Algorithm, el)
	if err != nil {
		return err
	}
	xml.canonicalizer = canonicalizer

	xml.cachedXml = el
	return nil
}

func (xml *CanonicalizationMethod) getXml() (*etree.Element, error) {
	el := etree.NewElement("CanonicalizationMethod")
	el.Space = xml.root().getElementSpace(XmlDSigNamespaceUri)

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
