package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func HandleRequest(w http.ResponseWriter, r *http.Request) {
	in := new(input)

	if err := json.NewDecoder(r.Body).Decode(in); err != nil {
		SendErrorResponse(w, err, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	if in.SecretParams.Config == nil {
		SendErrorResponse(w, errors.New("empty config"), "Configuration is missing", http.StatusBadRequest)
		return
	}

	client, err := New(*in.SecretParams.Config)
	if err != nil {
		SendErrorResponse(w, err, "Failed to create Secret Manager client", http.StatusInternalServerError)
		return
	}

	ctx := context.Background()
	operation := strings.ToLower(in.SecretParams.Action)

	var result interface{}

	switch operation {
	case "connect":
		result, _ = HandleConnect(ctx, client, in.SecretParams.Secret.Name)
	case "validate_ref":
		result, _ = HandleValidateRef(ctx, client, in.SecretParams.Secret.Name)
	case "fetch":
		result, _ = HandleFetch(ctx, client, *in.SecretParams.Secret)
	case "create":
		result, _ = HandleCreate(ctx, client, *in.SecretParams.Secret)
	case "update":
		result, _ = HandleUpsert(ctx, client, *in.SecretParams.Secret, in.SecretParams.ExistingSecret)
	case "rename":
		result, _ = HandleRename(ctx, client, *in.SecretParams.Secret, in.SecretParams.ExistingSecret)
	case "delete":
		result, _ = HandleDelete(ctx, client, *in.SecretParams.Secret)
	default:
		SendErrorResponse(w, errors.New("invalid action"), fmt.Sprintf("The specified action %s is not supported", operation), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
