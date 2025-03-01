package xmldsig

import (
	"strconv"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type SignatureMethod struct {
	Algorithm        string
	HMACOutputLength int
}

func (node *SignatureMethod) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "SignatureMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	node.Algorithm = el.SelectAttrValue("Algorithm", "")

	hmacOutputLengthElement, err := getOptionalSingleChildElement(el, "HMACOutputLength", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	if hmacOutputLengthElement != nil {
		hmacOutputLengthValue, err := strconv.Atoi(hmacOutputLengthElement.Text())
		if err != nil {
			return err
		}
		node.HMACOutputLength = hmacOutputLengthValue
	}

	return nil
}

func (node *SignatureMethod) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("SignatureMethod")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", node.Algorithm)

	if node.HMACOutputLength != 0 {
		hmacOutputLengthElement := el.CreateElement("HMACOutputLength")
		hmacOutputLengthElement.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)
		hmacOutputLengthElement.SetText(strconv.Itoa(node.HMACOutputLength))
	}

	return el, nil
}
