package secrets

import (
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

func getErrorType(err error) string {

	var errorType string

	// Check for specific AWS Secrets Manager error types
	var decryptionFailure *types.DecryptionFailure
	var internalServiceError *types.InternalServiceError
	var invalidParameterException *types.InvalidParameterException
	var invalidRequestException *types.InvalidRequestException
	var resourceNotFoundException *types.ResourceNotFoundException
	var limitExceededException *types.LimitExceededException
	var encryptionFailure *types.EncryptionFailure
	var resourceExistsException *types.ResourceExistsException
	var malformedPolicyDocumentException *types.MalformedPolicyDocumentException
	var preconditionNotMetException *types.PreconditionNotMetException

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
	case errors.As(err, &resourceExistsException):
		errorType = "ResourceExistsException"
	case errors.As(err, &malformedPolicyDocumentException):
		errorType = "MalformedPolicyDocumentException"
	case errors.As(err, &preconditionNotMetException):
		errorType = "PreconditionNotMetException"
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
