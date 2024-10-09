package secrets

import (
	"encoding/json"
	"net/http"
)

func NewErrorResponse(err error, message string, status int) ErrorResponse {
	return ErrorResponse{
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
