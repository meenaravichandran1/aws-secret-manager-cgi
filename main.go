package main

import (
	"encoding/json"
	"errors"
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

func main() {
	http.HandleFunc("/", handleRequest)
	cgi.Serve(http.DefaultServeMux)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// unmarshal the input
	in := new(input)

	if err := json.NewDecoder(r.Body).Decode(in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if in.Config == nil {
		http.Error(w, "Empty config", http.StatusBadRequest)
		return
	}

	client, err := newSecretsManagerClient(*in.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var result interface{}
	var handlerErr error

	switch in.Action {
	case "connect":
		result, handlerErr = handleConnect(client, *in.Secret.Name)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if handlerErr != nil {
		http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleConnect(client *secretsmanager.Client, name string) (bool, error) {
	_, err := fetchSecret(client, name)
	if err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			// this exception is expected. It means the credentials are correct, but can't find the resource
			// which means the connectivity to AWS Secrets Manger is ok.
			return true, nil
		}
		return false, err
	}
	return true, nil
}
