package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/samlsp"
)

var (
	oktaMetaUrl     = ""
	cyberArkMetaUrl = ""
	oneLoginMetaUrl = ""
	entityID        = "http://localhost:8080"
)

func main() {

	pfx := "./dp"
	keyPair, err := tls.LoadX509KeyPair(fmt.Sprintf("%s.crt", pfx), fmt.Sprintf("%s.key", pfx))
	if err != nil {
		panic(err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse(oneLoginMetaUrl)
	if err != nil {
		panic(err)
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(),
		http.DefaultClient,
		*idpMetadataURL)

	if err != nil {
		panic(err) // TODO handle error
	}
	rootURL, err := url.Parse(entityID)
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
		EntityID:    entityID,
	})

	app := http.HandlerFunc(hello)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)

	http.ListenAndServe(":8080", nil)
}

func hello(w http.ResponseWriter, r *http.Request) {
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}
	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}

	fmt.Fprintf(w, "Token contents, %+v!", sa.GetAttributes())
}
