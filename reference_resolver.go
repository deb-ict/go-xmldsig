package xmldsig

import (
	"context"
	"io"
)

type ResolveReferenceMethod func(ctx context.Context, reference *Reference) (io.Reader, error)

func RegisterReferenceElementResolver(prefix string, method ResolveReferenceMethod) {
	referenceElementResolvers[prefix] = method
}

func GetReferenceElementResolver(prefix string) (ResolveReferenceMethod, bool) {
	method, ok := referenceElementResolvers[prefix]
	return method, ok
}

func GetReferenceResolverPrefixes() []string {
	prefixes := make([]string, 0, len(referenceElementResolvers))
	for prefix := range referenceElementResolvers {
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}
