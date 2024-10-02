package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"net/http"
	"net/http/cgi"
)

// Sample handler for AWS secret manager
//
// Sample json input:
//
//	{
//	    "task": {
//	        "id": "67c0938c-9348-4c5e-8624-28218984e09g",
//	        "type": "secret/awsvault/fetch",
//	        "data": {
//	            "secrets": [
//	              {
//	                  "config": {
//	                       "address": "http://localhost:8200",
//	                       "token": "root"
//	                  },
//	                  "path": "secret/data/aws_secret",
//	                  "key": "aws_secret"
//		   			 }
//	            ]
//	        }
//	    }
//	}

// {
// "task": {
// "id": "67c0938c-9348-4c5e-8624-28218984e09f",
// "driver": "cgi",
// "config": {
// "repository": {
// "clone": "https://github.com/vistaarjuneja/user-cgi",
// "ref": "main"
// }
// },
// "type": "custom/user/find",
// "data": {
// "id": 1
// }
// }
// }
type SecretManagerConfig struct {
	Region    string `json:"region"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

type secret struct {
	Name *string `json:"name"`
}

type input struct {
	Action string               `json:"action"`
	Config *SecretManagerConfig `json:"config"`
	Secret *secret              `json:"secret"`
}

type ErrorResponse struct {
	Message string `json:"message"`
	Error   string `json:"error"`
	Status  int    `json:"status"`
}

func NewErrorResponse(err error, message string, status int) ErrorResponse {
	return ErrorResponse{
		Message: message,
		Error:   err.Error(),
		Status:  status,
	}
}

func main() {
	http.HandleFunc("/", handleRequest)
	cgi.Serve(http.DefaultServeMux)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	in := new(input)

	if err := json.NewDecoder(r.Body).Decode(in); err != nil {
		sendErrorResponse(w, err, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	if in.Config == nil {
		sendErrorResponse(w, errors.New("empty config"), "Configuration is missing", http.StatusBadRequest)
		return
	}

	client, err := newSecretsManagerClient(*in.Config)
	if err != nil {
		sendErrorResponse(w, err, "Failed to create Secrets Manager client", http.StatusInternalServerError)
		return
	}

	var result interface{}
	var handlerErr error

	switch in.Action {
	case "connect":
		result, handlerErr = handleConnect(client, *in.Secret.Name)
	default:
		sendErrorResponse(w, errors.New("invalid action"), "The specified action is not supported", http.StatusBadRequest)
		return
	}

	if handlerErr != nil {
		sendErrorResponse(w, handlerErr, "Operation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func sendErrorResponse(w http.ResponseWriter, err error, message string, status int) {
	errResp := NewErrorResponse(err, message, status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errResp)
}

func handleConnect(client *secretsmanager.Client, name string) (bool, error) {
	_, err := fetchSecret(client, name)
	if err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			return true, nil
		}
		return false, fmt.Errorf("failed to connect to AWS Secrets Manager: %w", err)
	}
	return true, nil
}
