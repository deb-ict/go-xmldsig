package xmldsig

import (
	"strconv"

	"github.com/beevik/etree"
)

type SignatureMethod struct {
	Algorithm        string
	HMACOutputLength int
	signedInfo       *SignedInfo
	cachedXml        *etree.Element
}

func newSignatureMethod(signedInfo *SignedInfo) *SignatureMethod {
	return &SignatureMethod{}
}

func (xml *SignatureMethod) root() *SignedXml {
	return xml.signedInfo.root()
}

func (xml *SignatureMethod) loadXml(el *etree.Element) error {
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

	xml.cachedXml = el
	return nil
}

func (xml *SignatureMethod) getXml() (*etree.Element, error) {
	el := etree.NewElement("SignatureMethod")
	el.Space = xml.root().getElementSpace(XmlDSigNamespaceUri)

	el.CreateAttr("Algorithm", xml.Algorithm)

	if xml.HMACOutputLength != 0 {
		hmacOutputLengthElement := el.CreateElement("HMACOutputLength")
		hmacOutputLengthElement.Space = xml.root().getElementSpace(XmlDSigNamespaceUri)
		hmacOutputLengthElement.SetText(strconv.Itoa(xml.HMACOutputLength))
	}

	return el, nil
}
