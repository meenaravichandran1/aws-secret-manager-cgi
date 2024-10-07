package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"net/http"
	"net/http/cgi"
	"strings"
)

// Sample handler for AWS secret manager
//
// Sample json input:
//
//{
//    "task": {
//        "id": "your-task-id",
//        "driver": "cgi",
//        "config": {
//            "repository": {
//                "clone": "https://github.com/meenaravichandran1/aws-secret-manager-cgi",
//                "ref": "main"
//            }
//        },
//        "type": "secret/aws/fetch",
//        "data": {
//            "action": "connect",
//            "config": {
//                "region": "us-east-1",
//                "access_key": "yourAccessKey",
//                "secret_key": "yourSecretKey"
//            },
//            "secret": {
//                "name": "your-secret-name"
//            }
//        }
//    }
//}

type SecretManagerConfig struct {
	Region    string `json:"region"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

type input struct {
	Action string               `json:"secret_operation"`
	Config *SecretManagerConfig `json:"store_config"`
	Secret *Secret              `json:"secret"`
}

type Secret struct {
	Name *string `json:"name"`
}

type ErrorResponse struct {
	Message string `json:"message"`
	Error   string `json:"error"`
	Status  int    `json:"status"`
}

type ErrorResponseDebug struct {
	Error   string      `json:"error"`
	Message string      `json:"message"`
	Details string      `json:"details,omitempty"` // Optional field for error details
	Input   interface{} `json:"input,omitempty"`   // Optional field for input object
}

func NewErrorResponse(err error, message string, status int) ErrorResponse {
	return ErrorResponse{
		Message: message,
		Error:   err.Error(),
		Status:  status,
	}
}

func NewErrorResponseDebug(err error, message string, status int, input interface{}) ErrorResponseDebug {
	return ErrorResponseDebug{
		Error:   http.StatusText(status),
		Message: message,
		Details: err.Error(),
		Input:   input,
	}
}

func main() {
	http.HandleFunc("/", handleRequest)
	cgi.Serve(http.DefaultServeMux)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	in := new(input)

	if err := json.NewDecoder(r.Body).Decode(in); err != nil {

		sendErrorResponseDebug(w, err, "Failed to decode request body", http.StatusBadRequest, in)
		return
	}

	if in.Config == nil {
		sendErrorResponseDebug(w, errors.New("empty config"), "Configuration is missing", http.StatusBadRequest, in)
		return
	}

	client, err := newSecretsManagerClient(*in.Config)
	if err != nil {
		sendErrorResponse(w, err, "Failed to create Secrets Manager client", http.StatusInternalServerError)
		return
	}

	var result interface{}
	var handlerErr error

	switch strings.ToLower(in.Action) {
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

func sendErrorResponseDebug(w http.ResponseWriter, err error, message string, status int, input interface{}) {
	errResp := NewErrorResponseDebug(err, message, status, input)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errResp)
}

func handleConnect(client *secretsmanager.Client, name string) (map[string]interface{}, error) {
	_, err := fetchSecret(client, name)
	if err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			return map[string]interface{}{"valid": true}, nil
		}
		return map[string]interface{}{"valid": false}, fmt.Errorf("failed to connect to AWS Secrets Manager: %w", err)
	}
	return map[string]interface{}{"valid": true}, nil
}
