package secrets

import (
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

	var result interface{}

	switch strings.ToLower(in.SecretParams.Action) {
	case "connect":
		result, _ = HandleConnect(client, *in.SecretParams.Secret.Name)
	default:
		SendErrorResponse(w, errors.New("invalid action"), "The specified action is not supported", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
