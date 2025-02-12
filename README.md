# go-xmldsig
XML Digital Signature

## Installation
Install `go-xmldsig` using `go get`:

```
$ go get -u github.com/deb-ict/go-xmldsig
```

## Reference
This code is based on repository [russellhaering/goxmldsig](https://github.com/russellhaering/goxmldsig) and C# SignedXml.  
**If u star this repository, please star the original code repository as well!**  

## Purpose
This code is a requirement for the [go-peppol](https://github.com/deb-ict/go-peppol) project where including mime attachment digest in the signature is required.  

## Generate a test certificate
`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365`