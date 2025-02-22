package xmldsig

import (
	"fmt"

	"github.com/beevik/etree"
)

type ChildElementNotFoundError struct {
	ParentTag   string
	ParentSpace string
	ChildTag    string
	ChildSpace  string
}

func (e *ChildElementNotFoundError) Error() string {
	return fmt.Sprintf("[%s]%s has no child element: [%s]%s", e.ParentSpace, e.ParentTag, e.ChildSpace, e.ChildTag)
}

func newChildElementNotFoundError(el *etree.Element, tag string, space string) *ChildElementNotFoundError {
	return &ChildElementNotFoundError{
		ParentSpace: el.NamespaceURI(),
		ParentTag:   el.Tag,
		ChildTag:    tag,
		ChildSpace:  space,
	}
}

type MultipleChildElementsFoundError struct {
	ParentTag   string
	ParentSpace string
	ChildTag    string
	ChildSpace  string
}

func (e *MultipleChildElementsFoundError) Error() string {
	return fmt.Sprintf("[%s]%s has multiple child elements: [%s]%s", e.ParentSpace, e.ParentTag, e.ChildSpace, e.ChildTag)
}

func NewMultipleChildElementsFoundError(el *etree.Element, tag string, space string) *MultipleChildElementsFoundError {
	return &MultipleChildElementsFoundError{
		ParentSpace: el.NamespaceURI(),
		ParentTag:   el.Tag,
		ChildTag:    tag,
		ChildSpace:  space,
	}
}
