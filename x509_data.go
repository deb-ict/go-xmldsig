package xmldsig

import (
	"crypto/x509"
	"encoding/base64"

	"github.com/beevik/etree"
)

type X509Data struct {
	SubjectName string
	Certificate string
	cachedXml   *etree.Element
}

func (xml *X509Data) GetCertificate() (*x509.Certificate, error) {
	certificateData, err := base64.StdEncoding.DecodeString(xml.Certificate)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(certificateData)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func (xml *X509Data) LoadXml(resolver XmlResolver, el *etree.Element) error {
	err := validateElement(el, "X509Data", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	xml.SubjectName = el.SelectElement("X509SubjectName").Text()
	xml.Certificate = el.SelectElement("X509Certificate").Text()

	xml.cachedXml = el
	return nil
}

func (xml *X509Data) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("X509Data")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	if xml.SubjectName != "" {
		subjectName := el.CreateElement("X509SubjectName")
		subjectName.SetText(xml.SubjectName)
	}
	if xml.Certificate != "" {
		certificate := el.CreateElement("X509Certificate")
		certificate.SetText(xml.Certificate)
	}

	return el, nil
}
