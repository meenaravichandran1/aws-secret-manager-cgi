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
	//logrus.SetFormatter(&logrus.TextFormatter{
	//	FullTimestamp: true,
	//})

	// TODO if remote logging is enabled in env var, set the bool from env var
	remoteLogger := gcplogger.NewGCPLoggerWithToken(logrus.StandardLogger(), &client.AccessTokenBean{
		ProjectId:            "qa-setup",
		TokenValue:           "replaced",
		ExpirationTimeMillis: 1730326818617,
	})

	// TODO set the bool from env var
	_, err := remoteLogger.StartGcpLoggerWithToken(context.TODO())
	if err != nil {
		return
	}

	http.HandleFunc("/", secrets.HandleRequest)
	err = cgi.Serve(http.DefaultServeMux)

	if err != nil {
		logrus.WithError(err).Fatal("Failed to serve CGI")
	}
}
