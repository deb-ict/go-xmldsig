package xmldsig

import (
	"strconv"

	"github.com/beevik/etree"
)

type SignatureMethod struct {
	Algorithm        string
	HMACOutputLength int
}

func (xml *SignatureMethod) LoadXml(resolver XmlResolver, el *etree.Element) error {
	err := validateElement(el, "SignatureMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.Algorithm = el.SelectAttrValue("Algorithm", "")

	hmacOutputLengthElement, err := getOptionalSingleChildElement(el, "HMACOutputLength", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	if hmacOutputLengthElement != nil {
		hmacOutputLengthValue, err := strconv.Atoi(hmacOutputLengthElement.Text())
		if err != nil {
			return err
		}
		xml.HMACOutputLength = hmacOutputLengthValue
	}

	return nil
}

func (xml *SignatureMethod) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("SignatureMethod")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", xml.Algorithm)

	if xml.HMACOutputLength != 0 {
		hmacOutputLengthElement := el.CreateElement("HMACOutputLength")
		hmacOutputLengthElement.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)
		hmacOutputLengthElement.SetText(strconv.Itoa(xml.HMACOutputLength))
	}

	return el, nil
}
