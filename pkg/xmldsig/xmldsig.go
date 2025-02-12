package xmldsig

import "errors"

const (
	XmlDSigNamespaceUri string = "http://www.w3.org/2000/09/xmldsig#"
)

var (
	ErrInvalidSignatureMethod = errors.New("invalid signature method")
	ErrInvalidDigestMethod    = errors.New("invalid digest method")
)

var (
	registeredTransforms map[string]CreateTransformMethod = map[string]CreateTransformMethod{
		"http://www.w3.org/2001/10/xml-exc-c14n#": NewExclusiveC14NTransform,
	}
	registeredCanonicalizers map[string]CreateCanonicalizerMethod = map[string]CreateCanonicalizerMethod{
		"http://www.w3.org/2001/10/xml-exc-c14n#": NewExclusiveC14NCanonicalizer,
	}
	referenceElementResolvers map[string]ResolveReferenceMethod = map[string]ResolveReferenceMethod{}
)

func CryptographicEquals(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	r := 0
	for i := range a {
		r |= (int(a[i]) - int(b[i]))
	}
	return (r == 0)
}
