package secrets

import (
	"context"
	"encoding/json"
	"errors"
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

	client, err := New(in.SecretParams.Config)
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
	case "fetch":
		result, _ = HandleFetch(ctx, client, *in.SecretParams.Secret.Name, in.SecretParams.Config)
	case "create":
		result, _ = HandleUpsert(ctx, client, in.SecretParams.Secret, nil, in.SecretParams.Config)
	case "update":
		result, _ = HandleUpsert(ctx, client, in.SecretParams.Secret, in.SecretParams.ExistingSecret, in.SecretParams.Config)
	case "rename":
		result, _ = HandleRename(ctx, client, in.SecretParams.Secret, in.SecretParams.ExistingSecret, in.SecretParams.Config)
	case "delete":
		result, _ = HandleDelete(ctx, client, in.SecretParams.Secret, in.SecretParams.Config)
	default:
		SendErrorResponse(w, errors.New("invalid action"), "The specified action is not supported", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
