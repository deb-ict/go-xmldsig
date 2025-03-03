
# go-xmldsig

[![Build & Test](https://github.com/deb-ict/go-xmldsig/actions/workflows/build.yml/badge.svg)](https://github.com/deb-ict/go-xmldsig/actions/workflows/build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=deb-ict_go-xmldsig&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=deb-ict_go-xmldsig)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=deb-ict_go-xmldsig&metric=coverage)](https://sonarcloud.io/summary/new_code?id=deb-ict_go-xmldsig)

XML digital signature

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