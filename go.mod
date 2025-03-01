module github.com/deb-ict/go-xmldsig

go 1.23.1

require (
	github.com/beevik/etree v1.5.0
	github.com/russellhaering/goxmldsig v1.4.0
)

require (
	github.com/deb-ict/go-xml v0.0.1-alpha // indirect
	github.com/deb-ict/go-xmlsecurity v0.0.1-alpha // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
)

replace (
	github.com/deb-ict/go-xml v0.0.1-alpha => ../go-xml
	github.com/deb-ict/go-xmlsecurity v0.0.1-alpha => ../go-xmlsecurity
)