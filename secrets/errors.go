package secrets

import (
	"aws-secret-manager-cgi/common"
	"encoding/json"
	"net/http"
)

func NewErrorResponse(err error, message string, status int) common.ErrorResponse {
	return common.ErrorResponse{
		Message: message,
		Error:   err.Error(),
		Status:  status,
	}
}

func SendErrorResponse(w http.ResponseWriter, err error, message string, status int) {
	errResp := NewErrorResponse(err, message, status)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(errResp)
}
