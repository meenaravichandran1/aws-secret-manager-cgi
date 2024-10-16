package secrets

import (
	"aws-secret-manager-cgi/awssecrets"
	"aws-secret-manager-cgi/common"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func HandleRequest(w http.ResponseWriter, r *http.Request) {
	in := new(common.Input)

	if err := json.NewDecoder(r.Body).Decode(in); err != nil {
		SendErrorResponse(w, err, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	if in.SecretParams.Config == nil {
		SendErrorResponse(w, errors.New("empty config"), "Configuration is missing", http.StatusBadRequest)
		return
	}

	secretManager, err := awssecrets.New(*in.SecretParams.Config)
	if err != nil {
		SendErrorResponse(w, err, "Failed to create AWS Secret Manager client", http.StatusInternalServerError)
		return
	}

	ctx := context.Background()
	operation := strings.ToLower(in.SecretParams.Action)

	var result interface{}

	switch operation {
	case "connect":
		result, _ = secretManager.Connect(ctx, in.SecretParams.Secret.Name)
	case "validate_ref":
		result, _ = secretManager.ValidateReference(ctx, in.SecretParams.Secret.Name)
	case "fetch":
		result, _ = secretManager.FetchSecret(ctx, *in.SecretParams.Secret)
	case "create":
		result, _ = secretManager.UpsertSecret(ctx, *in.SecretParams.Secret, nil)
	case "update":
		result, _ = secretManager.UpsertSecret(ctx, *in.SecretParams.Secret, in.SecretParams.ExistingSecret)
	case "rename":
		result, _ = secretManager.RenameSecret(ctx, *in.SecretParams.Secret, in.SecretParams.ExistingSecret)
	case "delete":
		result, _ = secretManager.DeleteSecret(ctx, *in.SecretParams.Secret)
	default:
		SendErrorResponse(w, errors.New("invalid action"), fmt.Sprintf("The specified action %s is not supported", operation), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
