package main

import (
	"aws-secret-manager-cgi/secrets"
	"net/http"
	"net/http/cgi"
)

func main() {
	http.HandleFunc("/", secrets.HandleRequest)
	cgi.Serve(http.DefaultServeMux)
}
