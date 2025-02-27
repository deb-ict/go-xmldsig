package xmldsig

import (
	"github.com/beevik/etree"
)

type XmlNode interface {
	LoadXml(resolver XmlResolver, el *etree.Element) error
	GetXml(resolver XmlResolver) (*etree.Element, error)
}
