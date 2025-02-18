package xmldsig

import (
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/beevik/etree"
)

type Reference struct {
	signedInfo   *SignedInfo
	uri          string
	digestMethod DigestMethod
	digestValue  []byte
	transforms   []Transform
	cachedXml    *etree.Element
}

func newReference(signedInfo *SignedInfo) *Reference {
	return &Reference{
		signedInfo: signedInfo,
	}
}

func (ref *Reference) root() *SignedXml {
	return ref.signedInfo.root()
}

func (ref *Reference) validateDigest() error {
	if ref.uri == "" || strings.HasPrefix(ref.uri, "#") {
		var element *etree.Element
		if ref.uri == "" {
			element = ref.root().document.Root()
		} else {
			elementId := ref.uri[1:]
			element = ref.root().document.FindElement("//*[@Id='" + elementId + "']")
		}
		if element == nil {
			return errors.New("element not found")
		}

		// Apply the transforms
		var transformedData []byte
		var transformError error
		for _, transform := range ref.transforms {
			if transformedData == nil {
				transformedData, transformError = transform.TransformXmlElement(element)
			} else {
				transformedData, transformError = transform.TransformData(transformedData)
			}
			if transformError != nil {
				return transformError
			}
		}

		// Calculate the digest
		digestMethod, err := ref.digestMethod.CreateHashAlgorithm()
		if err != nil {
			return err
		}
		digestMethod.Write(transformedData)
		digestValue := digestMethod.Sum(nil)
		if CryptographicEquals(digestValue, ref.digestValue) {
			return nil
		}
	} else {
		prefixes := GetReferenceResolverPrefixes()
		for _, prefix := range prefixes {
			if strings.HasPrefix(ref.uri, prefix) {
				if method, ok := GetReferenceElementResolver(prefix); ok {
					reader, err := method(ref)
					if err != nil {
						return err
					}

					// Apply the transforms
					transformedData, transformError := io.ReadAll(reader)
					if transformError != nil {
						return transformError
					}
					for _, transform := range ref.transforms {
						transformedData, transformError = transform.TransformData(transformedData)
						if transformError != nil {
							return transformError
						}
					}

					// Calculate the digest
					digestMethod, err := ref.digestMethod.CreateHashAlgorithm()
					if err != nil {
						return err
					}
					digestMethod.Write(transformedData)
					digestValue := digestMethod.Sum(nil)
					if CryptographicEquals(digestValue, ref.digestValue) {
						return nil
					}
				}
			}
		}
	}

	return errors.New("digest validation failed")
}

func (ref *Reference) loadXml(el *etree.Element) error {
	var err error

	if el == nil {
		return errors.New("element cannot be nil")
	}
	if el.Tag != "Reference" || el.NamespaceURI() != XmlDSigNamespaceUri {
		return errors.New("element is not a reference element")
	}

	// Get the reference attributes
	ref.uri = el.SelectAttrValue("URI", "")

	// Get the transform list element
	transformsElement := el.SelectElements("Transforms")
	if len(transformsElement) != 1 {
		return errors.New("element does not contain a single Transforms element")
	}

	// Get the transforms
	transformElements := transformsElement[0].SelectElements("Transform")
	for _, transformElement := range transformElements {
		algorithm := transformElement.SelectAttrValue("Algorithm", "")

		// Create the transform
		transform, err := GetTransform(algorithm, ref)
		if err != nil {
			return err
		}
		err = transform.LoadXml(transformElement)
		if err != nil {
			return err
		}
		ref.transforms = append(ref.transforms, transform)
	}

	// Get the digest method
	digestMethodElements := el.SelectElements("DigestMethod")
	if len(digestMethodElements) != 1 {
		return errors.New("element does not contain a single DigestMethod element")
	}
	digestMethodAlgorithm := digestMethodElements[0].SelectAttrValue("Algorithm", "")
	digestMethod, err := GetDigestMethod(digestMethodAlgorithm)
	if err != nil {
		return err
	}
	ref.digestMethod = digestMethod

	// Get the digest value
	digestValueElements := el.SelectElements("DigestValue")
	if len(digestValueElements) != 1 {
		return errors.New("element does not contain a single DigestValue element")
	}
	ref.digestValue, err = base64.StdEncoding.DecodeString(digestValueElements[0].Text())
	if err != nil {
		return err
	}

	ref.cachedXml = el
	return nil
}
