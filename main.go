package main

import (
	"aws-secret-manager-cgi/secrets"
	"context"
	"github.com/harness/runner/delegateshell/client"
	"github.com/harness/runner/logger/gcplogger"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/cgi"
	"os"
	"strconv"
)

func main() {
	handler := &secrets.Handler{}

	logrus.SetReportCaller(true)
	logrus.SetFormatter(&logrus.JSONFormatter{})

	isRemoteLoggingEnabled, err := strconv.ParseBool(os.Getenv("ENABLE_REMOTE_LOGGING"))
	if err != nil {
		isRemoteLoggingEnabled = false
	}
	if isRemoteLoggingEnabled {
		projectId := os.Getenv("PROJECT_ID")
		if projectId == "" {
			logrus.Println("Environment variable PROJECT_ID is not set. Cannot publish logs to remote")
			return
		}

		accessToken := os.Getenv("ACCESS_TOKEN")
		if accessToken == "" {
			logrus.Println("Environment variable ACCESS_TOKEN is not set. Cannot publish logs to remote")
			return
		}

		expiresAtStr := os.Getenv("EXPIRES_AT")
		if expiresAtStr == "" {
			logrus.Println("Environment variable EXPIRES_AT is not set. Cannot publish logs to remote")
			return
		}
		expiresAt, err := strconv.ParseInt(os.Getenv("EXPIRES_AT"), 10, 64)
		if err != nil {
			logrus.Printf("Failed to parse EXPIRES_AT: %v", err)
			return
		}

		remoteLogger := gcplogger.NewGCPLoggerWithToken(logrus.StandardLogger(), &client.AccessTokenBean{
			ProjectId:            projectId,
			TokenValue:           accessToken,
			ExpirationTimeMillis: expiresAt,
		})

		_, err = remoteLogger.StartGcpLoggerWithToken(context.TODO())
		if err != nil {
			return
		}
		logrus.Infoln("Publishing cgi logs to remote")
		handler.RemoteLogger = remoteLogger
	}

	http.HandleFunc("/", handler.HandleRequest)
	err = cgi.Serve(http.DefaultServeMux)

	if err != nil {
		logrus.WithError(err).Fatal("Failed to serve CGI")
	}
}
