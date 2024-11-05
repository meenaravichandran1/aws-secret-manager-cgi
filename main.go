package main

import (
	"aws-secret-manager-cgi/secrets"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/cgi"
)

func main() {
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&logrus.JSONFormatter{})

	http.HandleFunc("/", secrets.HandleRequest)
	err := cgi.Serve(http.DefaultServeMux)

	if err != nil {
		logrus.WithError(err).Fatal("Failed to serve CGI")
	}
}
