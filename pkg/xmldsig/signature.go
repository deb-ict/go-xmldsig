package xmldsig

import (
	"encoding/base64"
	"errors"

	"github.com/beevik/etree"
)

type Signature struct {
	signedXml      *SignedXml
	signedInfo     *SignedInfo
	cachedXml      *etree.Element
	signatureValue []byte
}

func newSignature(signedXml *SignedXml) *Signature {
	return &Signature{
		signedXml: signedXml,
	}
}

func (sig *Signature) root() *SignedXml {
	return sig.signedXml
}

func (sig *Signature) loadXml(el *etree.Element) error {
	if el == nil {
		return errors.New("element cannot be nil")
	}
	if el.Tag != "Signature" || el.NamespaceURI() != XmlDSigNamespaceUri {
		return errors.New("element is not a signature element")
	}

	// Get the signed info
	signedInfoElements := el.SelectElements("SignedInfo")
	if len(signedInfoElements) != 1 {
		return errors.New("element does not contain a single SignedInfo element")
	}
	sig.signedInfo = newSignedInfo(sig)
	err := sig.signedInfo.loadXml(signedInfoElements[0])
	if err != nil {
		return err
	}

	// Get the signature value
	signatureValueElements := el.SelectElements("SignatureValue")
	if len(signatureValueElements) != 1 {
		return errors.New("element does not contain a single SignatureValue element")
	}
	signatureValue, err := base64.StdEncoding.DecodeString(signatureValueElements[0].Text())
	if err != nil {
		return err
	}
	sig.signatureValue = signatureValue

	// Get the optional key info
	//TODO: keyInfoElements := el.SelectElements("KeyInfo[namespace-uri()='" + XmlDSigNamespaceUri + "']")

	sig.cachedXml = el
	return nil
}
