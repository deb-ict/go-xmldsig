package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xmldsig/pkg/xmldsig"
)

func main() {
	// Parse the command line arguments
	var xmlPath string
	var pemPath string
	flag.StringVar(&xmlPath, "xml", "", "The path to the xml file to validate")
	flag.StringVar(&pemPath, "pem", "", "The path to the pem file to use for signature validation")
	flag.Parse()

	// Check if the XML and PFX paths are provided
	if xmlPath == "" || pemPath == "" {
		flag.Usage()
		return
	}

	// Load the certificate
	crtData, err := os.ReadFile(pemPath)
	if err != nil {
		log.Fatalf("Failed to read PEM file: %v", err)
	}
	crtBlock, _ := pem.Decode(crtData)
	cert, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	log.Printf("Certificate loaded: %s", cert.Subject)

	// Load the XML file
	doc := etree.NewDocument()
	err = doc.ReadFromFile(xmlPath)
	if err != nil {
		log.Fatalf("Failed to read XML file: %v", err)
	}

	// Load the signed XML
	signedXml, err := xmldsig.LoadSignedXml(doc)
	if err != nil {
		log.Fatalf("Failed to load signed XML: %v", err)
	}

	// Validate the signature
	err = signedXml.ValidateSignature(cert)
	if err != nil {
		log.Fatalf("Failed to validate signature: %v", err)
	}

	log.Println("Signature is valid")
}
