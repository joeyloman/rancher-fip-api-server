// Package errors provides standardized JSON error handling utilities.
package errors

import (
	"encoding/json"
	"net/http"
)

// APIError represents a standard API error response.
type APIError struct {
	// Code is the HTTP status code.
	Code int `json:"code"`
	// Message is a human-readable error message.
	Message string `json:"message"`
}

// WriteJSONError writes a standard JSON error response to the http.ResponseWriter.
func WriteJSONError(w http.ResponseWriter, code int, message string) {
	errResponse := APIError{
		Code:    code,
		Message: message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(errResponse)
}
