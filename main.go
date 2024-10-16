package main

import (
	"aws-secret-manager-cgi/secrets"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/http/cgi"
)

func main() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	log.Info("Starting CGI application")

	http.HandleFunc("/", secrets.HandleRequest)
	err := cgi.Serve(http.DefaultServeMux)

	if err != nil {
		log.WithError(err).Fatal("Failed to serve CGI application")
	}
}
