package main

import (
	"aws-secret-manager-cgi/secrets"
	"context"
	"github.com/harness/runner/delegateshell/client"
	"github.com/harness/runner/logger/gcplogger"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/cgi"
)

func main() {
	// TODO if remote logging is enabled in env var, set the bool from env var
	// TODO token value set as env var
	remoteLogger := gcplogger.NewGCPLoggerWithToken(logrus.StandardLogger(), &client.AccessTokenBean{
		ProjectId:            "qa-setup",
		TokenValue:           "replaced",
		ExpirationTimeMillis: 1730326818617,
	})

	_, err := remoteLogger.StartGcpLoggerWithToken(context.TODO())
	if err != nil {
		return
	}

	handler := &secrets.Handler{RemoteLogger: remoteLogger}
	http.HandleFunc("/", handler.HandleRequest)
	err = cgi.Serve(http.DefaultServeMux)

	if err != nil {
		logrus.WithError(err).Fatal("Failed to serve CGI")
	}
}
