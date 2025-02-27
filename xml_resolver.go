package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
)

type XmlTypeConstructor func(resolver XmlResolver) (XmlNode, error)

type XmlResolver interface {
	GetDocument() *etree.Document
	SetNamespacePrefix(prefix string, uri string)
	GetElementSpace(uri string) string
	RegisterTypeConstructor(uri string, tag string, ctor XmlTypeConstructor)
	GetTypeConstructor(uri string, tag string) (XmlTypeConstructor, error)
}

type xmlResolver struct {
	doc              *etree.Document
	uris             map[string]string
	prefixes         map[string]string
	typeConstructors []*xmlTypeEntry
}

type xmlTypeEntry struct {
	uri         string
	tag         string
	constructor XmlTypeConstructor
}

func NewXmlResolver(doc *etree.Document) XmlResolver {
	return &xmlResolver{
		doc:              doc,
		uris:             make(map[string]string),
		prefixes:         make(map[string]string),
		typeConstructors: make([]*xmlTypeEntry, 0),
	}
}

func (resolver *xmlResolver) GetDocument() *etree.Document {
	return resolver.doc
}

func (resolver *xmlResolver) SetNamespacePrefix(prefix string, uri string) {
	resolver.prefixes[uri] = prefix
	resolver.uris[prefix] = uri
}

func (resolver *xmlResolver) GetElementSpace(uri string) string {
	prefix, found := resolver.prefixes[uri]
	if !found {
		return uri
	}
	return prefix
}

func (resolver *xmlResolver) RegisterTypeConstructor(uri string, tag string, ctor XmlTypeConstructor) {
	entry, ok := resolver.getTypeConstructor(uri, tag)
	if !ok {
		entry = &xmlTypeEntry{
			uri: uri,
			tag: tag,
		}
		resolver.typeConstructors = append(resolver.typeConstructors, entry)
	}
	entry.constructor = ctor
}

func (resolver *xmlResolver) GetTypeConstructor(uri string, tag string) (XmlTypeConstructor, error) {
	entry, ok := resolver.getTypeConstructor(uri, tag)
	if !ok {
		return nil, errors.New("no type constructor for namespace")
	}
	return entry.constructor, nil
}

func (resolver *xmlResolver) getTypeConstructor(uri string, tag string) (*xmlTypeEntry, bool) {
	for _, entry := range resolver.typeConstructors {
		if entry.uri == uri && entry.tag == tag {
			return entry, true
		}
	}
	return nil, false
}
