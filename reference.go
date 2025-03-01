package xmldsig

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
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

func (node *Reference) GetUriWithoutPrefix(prefix string) string {
	if strings.HasPrefix(node.Uri, prefix) {
		return node.Uri[len(prefix):]
	}
	return node.Uri
}

func (node *Reference) validateDigest(ctx context.Context, doc *etree.Document) error {
	digestBytes, err := base64.StdEncoding.DecodeString(node.DigestValue)
	if err != nil {
		return err
	}

	if node.Uri == "" || strings.HasPrefix(node.Uri, "#") {
		var element *etree.Element
		if node.Uri == "" {
			element = doc.Root()
		} else {
			elementId := node.Uri[1:]
			element = doc.FindElement("//*[@Id='" + elementId + "']")
		}
		if element == nil {
			return errors.New("element not found")
		}

		// Apply the transforms
		data, err := node.Transforms.transformXmlElement(ctx, element)
		if err != nil {
			return err
		}

		// Calculate the digest
		digestMethod, err := GetDigestMethod(node.DigestMethod.Algorithm)
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
			if strings.HasPrefix(node.Uri, prefix) {
				if method, ok := GetReferenceElementResolver(prefix); ok {
					reader, err := method(ctx, node)
					if err != nil {
						return err
					}

					// Apply the transforms
					data, err := io.ReadAll(reader)
					if err != nil {
						return err
					}
					data, err = node.Transforms.transformData(ctx, data)
					if err != nil {
						return err
					}

					// Calculate the digest
					digestMethod, err := GetDigestMethod(node.DigestMethod.Algorithm)
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

func (node *Reference) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := validateElement(el, "Reference", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}

	// Get the reference attributes
	node.Id = el.SelectAttrValue("Id", "")
	node.Uri = el.SelectAttrValue("URI", "")
	node.Type = el.SelectAttrValue("Type", "")

	// Get the transform list element
	transformsElement, err := getOptionalSingleChildElement(el, "Transforms", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	node.Transforms = &Transforms{}
	err = node.Transforms.LoadXml(resolver, transformsElement)
	if err != nil {
		return err
	}

	// Get the digest method
	digestMethodElement, err := getSingleChildElement(el, "DigestMethod", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	node.DigestMethod = &DigestMethod{}
	err = node.DigestMethod.LoadXml(resolver, digestMethodElement)
	if err != nil {
		return err
	}

	// Get the digest value
	digestValueElement, err := getSingleChildElement(el, "DigestValue", XmlDSigNamespaceUri)
	if err != nil {
		return err
	}
	node.DigestValue = digestValueElement.Text()

	return nil
}

func (node *Reference) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("Reference")
	el.Space = resolver.GetNamespacePrefix(XmlDSigNamespaceUri)

	// Write the reference attributes
	if node.Id != "" {
		el.CreateAttr("Id", node.Id)
	}
	if node.Uri != "" {
		el.CreateAttr("URI", node.Uri)
	}
	if node.Type != "" {
		el.CreateAttr("Type", node.Type)
	}

	// Write the transform list
	if node.Transforms != nil {
		transformElement, err := node.Transforms.GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(transformElement)
	}

	// Write the digest method
	if node.DigestMethod == nil {
		return nil, errors.New("reference does not contain a DigestMethod element")
	}
	digestMethodElement, err := node.DigestMethod.GetXml(resolver)
	if err != nil {
		return nil, err
	}
	el.AddChild(digestMethodElement)

	// Write the digest value
	if node.DigestValue == "" {
		return nil, errors.New("reference does not contain a DigestValue element")
	}
	digestValueElement := etree.NewElement("DigestValue")
	digestValueElement.SetText(node.DigestValue)
	el.AddChild(digestValueElement)

	return el, nil
}
