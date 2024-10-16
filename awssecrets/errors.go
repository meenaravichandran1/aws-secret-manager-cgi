package awssecrets

import (
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

func getErrorType(err error) string {

	var errorType string

	// Check for specific AWS Secrets Manager error types, this is used to provide hints and suggestions
	var decryptionFailure *types.DecryptionFailure
	var internalServiceError *types.InternalServiceError
	var invalidParameterException *types.InvalidParameterException
	var invalidRequestException *types.InvalidRequestException
	var resourceNotFoundException *types.ResourceNotFoundException
	var limitExceededException *types.LimitExceededException
	var encryptionFailure *types.EncryptionFailure

	switch {
	case errors.As(err, &decryptionFailure):
		errorType = "DecryptionFailure"
	case errors.As(err, &internalServiceError):
		errorType = "InternalServiceError"
	case errors.As(err, &invalidParameterException):
		errorType = "InvalidParameterException"
	case errors.As(err, &invalidRequestException):
		errorType = "InvalidRequestException"
	case errors.As(err, &resourceNotFoundException):
		errorType = "ResourceNotFoundException"
	case errors.As(err, &limitExceededException):
		errorType = "LimitExceededException"
	case errors.As(err, &encryptionFailure):
		errorType = "EncryptionFailure"
	default:
		// For other error types, try to get more information
		var smithyErr smithy.APIError
		if errors.As(err, &smithyErr) {
			errorType = smithyErr.ErrorCode()
		} else {
			errorType = "UnknownError"
		}
	}
	return errorType
}
