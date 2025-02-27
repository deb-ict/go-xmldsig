package xmldsig

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/beevik/etree"
)

type Reference struct {
	Id           string
	Uri          string
	Type         string
	Transforms   *Transforms
	DigestMethod *DigestMethod
	DigestValue  string
	cachedXml    *etree.Element
}

func (xml *Reference) GetUriWithoutPrefix(prefix string) string {
	if strings.HasPrefix(xml.Uri, prefix) {
		return xml.Uri[len(prefix):]
	}
	return xml.Uri
}

func (xml *Reference) validateDigest(ctx context.Context, doc *etree.Document) error {
	digestBytes, err := base64.StdEncoding.DecodeString(xml.DigestValue)
	if err != nil {
		return err
	}

	if xml.Uri == "" || strings.HasPrefix(xml.Uri, "#") {
		var element *etree.Element
		if xml.Uri == "" {
			element = doc.Root()
		} else {
			elementId := xml.Uri[1:]
			element = doc.FindElement("//*[@Id='" + elementId + "']")
		}
		if element == nil {
			return errors.New("element not found")
		}

		// Apply the transforms
		data, err := xml.Transforms.transformXmlElement(ctx, element)
		if err != nil {
			return err
		}

		// Calculate the digest
		digestMethod, err := GetDigestMethod(xml.DigestMethod.Algorithm)
		if err != nil {
			return err
		}
		digestAlgorithm, err := digestMethod.CreateHashAlgorithm()
		if err != nil {
			return err
		}
		digestAlgorithm.Write(data)
		digestValue := digestAlgorithm.Sum(nil)
		if CryptographicEquals(digestValue, digestBytes) {
			return nil
		}
	} else {
		prefixes := GetReferenceResolverPrefixes()
		for _, prefix := range prefixes {
			if strings.HasPrefix(xml.Uri, prefix) {
				if method, ok := GetReferenceElementResolver(prefix); ok {
					reader, err := method(ctx, xml)
					if err != nil {
						return err
					}

					// Apply the transforms
					data, err := io.ReadAll(reader)
					if err != nil {
						return err
					}
					data, err = xml.Transforms.transformData(ctx, data)
					if err != nil {
						return err
					}

					// Calculate the digest
					digestMethod, err := GetDigestMethod(xml.DigestMethod.Algorithm)
					if err != nil {
						return err
					}
					digestAlgorithm, err := digestMethod.CreateHashAlgorithm()
					if err != nil {
						return err
					}
					digestAlgorithm.Write(data)
					digestValue := digestAlgorithm.Sum(nil)
					if CryptographicEquals(digestValue, digestBytes) {
						return nil
					}
				}
			}
		}
	}

	return errors.New("digest validation failed")
}

func (xml *Reference) LoadXml(resolver XmlResolver, el *etree.Element) error {
	err := validateElement(el, "Reference", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	// Get the reference attributes
	xml.Id = el.SelectAttrValue("Id", "")
	xml.Uri = el.SelectAttrValue("URI", "")
	xml.Type = el.SelectAttrValue("Type", "")

	// Get the transform list element
	transformsElement, err := getOptionalSingleChildElement(el, "Transforms", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	xml.Transforms = &Transforms{}
	err = xml.Transforms.LoadXml(resolver, transformsElement)
	if err != nil {
		return err
	}

	// Get the digest method
	digestMethodElement, err := getSingleChildElement(el, "DigestMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	xml.DigestMethod = &DigestMethod{}
	err = xml.DigestMethod.LoadXml(resolver, digestMethodElement)
	if err != nil {
		return err
	}

	// Get the digest value
	digestValueElement, err := getSingleChildElement(el, "DigestValue", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	xml.DigestValue = digestValueElement.Text()

	return nil
}

func (xml *Reference) GetXml(resolver XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("Reference")
	el.Space = resolver.GetElementSpace(XmlDSigNamespaceUri)

	// Write the reference attributes
	if xml.Id != "" {
		el.CreateAttr("Id", xml.Id)
	}
	if xml.Uri != "" {
		el.CreateAttr("URI", xml.Uri)
	}
	if xml.Type != "" {
		el.CreateAttr("Type", xml.Type)
	}

	// Write the transform list
	if xml.Transforms != nil {
		transformElement, err := xml.Transforms.GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(transformElement)
	}

	// Write the digest method
	if xml.DigestMethod == nil {
		return nil, errors.New("reference does not contain a DigestMethod element")
	}
	digestMethodElement, err := xml.DigestMethod.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(digestMethodElement)

	// Write the digest value
	if xml.DigestValue == "" {
		return nil, errors.New("reference does not contain a DigestValue element")
	}
	digestValueElement := etree.NewElement("DigestValue")
	digestValueElement.SetText(xml.DigestValue)
	el.AddChild(digestValueElement)

	return el, nil
}
