package xmldsig

import (
	"crypto/x509"
	"errors"

	"github.com/beevik/etree"
)

type SignedInfo struct {
	signature       *Signature
	canonicalizer   Canonicalizer
	signatureMethod SignatureMethod
	cachedXml       *etree.Element
	references      []*Reference
}

func newSignedInfo(signature *Signature) *SignedInfo {
	return &SignedInfo{
		signature: signature,
	}
}

func (si *SignedInfo) root() *SignedXml {
	return si.signature.root()
}

func (si *SignedInfo) validateDigests() error {
	for _, reference := range si.references {
		err := reference.validateDigest()
		if err != nil {
			return err
		}
	}
	return nil
}

func (si *SignedInfo) validateSignature(cert *x509.Certificate) error {
	canonicalizedData, err := si.canonicalizer.Canonicalize(si.cachedXml)
	if err != nil {
		return err
	}

	signatureAlgorithm, err := si.signatureMethod.GetSignatureAlgorithm()
	if err != nil {
		return err
	}

	err = cert.CheckSignature(signatureAlgorithm, canonicalizedData, si.signature.signatureValue)
	if err != nil {
		return err
	}

	return nil
}

func (si *SignedInfo) loadXml(el *etree.Element) error {
	if el == nil {
		return errors.New("element cannot be nil")
	}
	if el.Tag != "SignedInfo" || el.NamespaceURI() != XmlDSigNamespaceUri {
		return errors.New("element is not a signed info element")
	}

	// Get the canonicalization method
	canonicalizationMethodElements := el.SelectElements("CanonicalizationMethod")
	if len(canonicalizationMethodElements) != 1 {
		return errors.New("element does not contain a single CanonicalizationMethod element")
	}
	canonicalizationMethod := canonicalizationMethodElements[0].SelectAttrValue("Algorithm", "")
	canonicalizer, err := GetCanonicalizer(canonicalizationMethod, canonicalizationMethodElements[0])
	if err != nil {
		return err
	}
	si.canonicalizer = canonicalizer

	// Get the signature method
	signatureMethodElements := el.SelectElements("SignatureMethod")
	if len(signatureMethodElements) != 1 {
		return errors.New("element does not contain a single SignatureMethod element")
	}
	signatureMethodAlgorithm := signatureMethodElements[0].SelectAttrValue("Algorithm", "")
	signatureMethod, err := GetSignatureMethod(signatureMethodAlgorithm)
	if err != nil {
		return err
	}
	si.signatureMethod = signatureMethod

	// Get the references
	referenceElements := el.SelectElements("Reference")
	for _, referenceElement := range referenceElements {
		reference := newReference(si)
		err := reference.loadXml(referenceElement)
		if err != nil {
			return err
		}
		si.references = append(si.references, reference)
	}

	si.cachedXml = el
	return nil
}
