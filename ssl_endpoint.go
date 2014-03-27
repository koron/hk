package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

var cmdSSLEndpoint = &Command{
	Run:      runSSLEndpoint,
	Usage:    "ssl-endpoint",
	NeedsApp: true,
	Category: "ssl",
	Short:    "show ssl endpoint info",
	Long:     `Show SSL endpoint and certificate information.`,
}

func runSSLEndpoint(cmd *Command, args []string) {
	if len(args) != 0 {
		cmd.printUsage()
		os.Exit(2)
	}
	endpoints, err := client.SSLEndpointList(mustApp(), nil)
	must(err)

	if len(endpoints) == 0 {
		return
	}

	chain, err := decodeCertChain(endpoints[0].CertificateChain)
	must(err)

	fmt.Println("Hostname:       ", endpoints[0].Cname)
	fmt.Println("Common Name(s): ", strings.Join(chain.CommonNames(), ", "))
	fmt.Println("Expires:        ", chain.Expires().UTC().Format(time.RFC3339))
}

type x509Chain []x509.Certificate

func (xc *x509Chain) CommonNames() []string {
	if xc == nil || len(*xc) == 0 {
		return []string{}
	}
	return (*xc)[0].DNSNames
}

func (xc *x509Chain) Expires() time.Time {
	if xc == nil || len(*xc) == 0 {
		return time.Time{}
	}
	return (*xc)[0].NotAfter
}

func decodeCertChain(chainPEM string) (chain x509Chain, err error) {
	certPEMBlock := []byte(chainPEM)
	var certDERBlock *pem.Block
	var cert tls.Certificate

	for {
		certDERBlock, certPEMBlock = pem.Decode([]byte(certPEMBlock))
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		err = errors.New("failed to parse certificate PEM data")
		return
	}

	var x509Cert *x509.Certificate
	for _, c := range cert.Certificate {
		x509Cert, err = x509.ParseCertificate(c)
		if err != nil {
			return
		}
		chain = append(chain, *x509Cert)
	}
	return
}
