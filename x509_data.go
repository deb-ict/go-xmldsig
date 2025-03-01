package xmldsig

import (
	"crypto/x509"
	"encoding/base64"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type X509Data struct {
	SubjectName string
	Certificate string
	cachedXml   *etree.Element
}

func (node *X509Data) GetX509Certificate(resolver xml.XmlResolver) (*x509.Certificate, error) {
	certificateData, err := base64.StdEncoding.DecodeString(node.Certificate)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(certificateData)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func (node *X509Data) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "X509Data", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	node.SubjectName = el.SelectElement("X509SubjectName").Text()
	node.Certificate = el.SelectElement("X509Certificate").Text()

	node.cachedXml = el
	return nil
}

func (node *X509Data) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("X509Data")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	if node.SubjectName != "" {
		subjectName := el.CreateElement("X509SubjectName")
		subjectName.SetText(node.SubjectName)
	}
	if node.Certificate != "" {
		certificate := el.CreateElement("X509Certificate")
		certificate.SetText(node.Certificate)
	}

	return el, nil
}
