package xmldsig

import (
	"github.com/deb-ict/go-xml"
)

type SignatureValue struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	Attrs   []*xml.Attr `xml:",any,attr"`
	Id      string      `xml:"Id,attr,omitempty"`
	Value   string      `xml:",chardata"`
}
