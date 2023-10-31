package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
)

var (
	oktaMetaUrl     = "https://trial-6305170.okta.com/app/exk8vtya0wTrHX0X2697/sso/saml/metadata"
	cyberArkMetaUrl = "https://abb4702.id.cyberark.cloud/saasManage/DownloadSAMLMetadataForApp?appkey=1438e2ac-f315-49a9-a9a6-e175f0f9fc24&customerid=ABB4702"
	oneLoginMetaUrl = "https://app.onelogin.com/saml/metadata/86e6a367-81df-4635-8ec4-0053e2955c88"
	entityID        = "http://localhost:8080"
)

func main() {
	router := gin.Default()

	router.GET("/auth", PrepareSamlRequest())
	router.POST("/auth/saml/acs", ParseSamlResponse())
	router.Run(":8080")
	//app := http.HandlerFunc(hello)
	//http.Get("/auth", PrepareSamlRequest(samlSP))
	//http.Handle("/auth", PrepareSamlRequest())
	//http.Handle("/auth", samlSP.RequireAccount(app))
	//http.Handle("/auth/saml/", ParseSamlResponse())

}

func SamlClient(pfx string) *samlsp.Middleware {
	keyPair, err := tls.LoadX509KeyPair(fmt.Sprintf("%s.crt", pfx), fmt.Sprintf("%s.key", pfx))
	if err != nil {
		panic(err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse(cyberArkMetaUrl)
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

	acsUrl, _ := url.Parse("http://localhost:8080/auth/saml/acs")
	samlSP.ServiceProvider.AcsURL = *acsUrl
	return samlSP
}

func PrepareSamlRequest() gin.HandlerFunc {
	log.Println("PrepareSamlRequest...")
	samlSP := SamlClient("./dp")
	return gin.HandlerFunc(func(c *gin.Context) {
		c.SetCookie("saml-test", "1234", 3600, "/auth/saml/acs", "localhost", false, true)
		samlSP.HandleStartAuthFlow(c.Writer, c.Request)
	})
}

func ParseSamlResponse() gin.HandlerFunc {
	samlSP := SamlClient("./dp")
	fmt.Println("ParseSamlResponse...")
	return gin.HandlerFunc(func(c *gin.Context) {
		w := c.Writer
		r := c.Request
		/*
			c, err := r.Cookie("saml-test")

				if err != nil {
					fmt.Println("Cookie error: ", err)
					return // TODO handle error
				}
				if c.Value != "1234" {
					fmt.Println("Cookie value error")

				}*/
		err := r.ParseForm()
		if err != nil {
			fmt.Println("ParseForm error: ", err)
			return
		}
		indexID := r.Form.Get("RelayState")

		fmt.Printf("indexID: %+v\n", indexID)
		trackedRequest, err := samlSP.RequestTracker.GetTrackedRequest(r, indexID)
		if err != nil {
			fmt.Println("GetTrackedRequest error: ", err)
		}

		fmt.Printf("trackedRequest: %+v\n", trackedRequest)
		if err := samlSP.RequestTracker.StopTrackingRequest(w, r, indexID); err != nil {
			fmt.Println("StopTrackingRequest error: ", err)
		}

		assertion, err := samlSP.ServiceProvider.ParseResponse(r, []string{trackedRequest.SAMLRequestID})

		if err != nil {
			fmt.Println("ParseResponse error: ", err)
			return
		}

		attrs := map[string][]string{}

		for i := range assertion.AttributeStatements[0].Attributes {
			key := assertion.AttributeStatements[0].Attributes[i].Name
			value := []string{}
			for val := range assertion.AttributeStatements[0].Attributes[i].Values {
				value = append(value, assertion.AttributeStatements[0].Attributes[i].Values[val].Value)
			}
			attrs[key] = value
		}

		fmt.Fprintf(w, "First Name: %s\n", attrs["first_name"][0])
		fmt.Fprintf(w, "Last Name: %s\n", attrs["last_name"][0])
		fmt.Fprintf(w, "Email: %s\n", attrs["email"][0])
		fmt.Fprintf(w, "Groups: %s\n", strings.Join(attrs["groups"], ","))
		fmt.Fprintf(w, "UserId: %s\n", attrs["user_id"][0])

		//http.Redirect(w, r, c.Path, http.StatusFound)
	})
}
