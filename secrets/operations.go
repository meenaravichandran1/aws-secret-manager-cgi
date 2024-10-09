package secrets

import (
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

func HandleConnect(client *secretsmanager.Client, name string) (*ValidationResponse, error) {
	_, err := getSecret(client, name)
	if err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			return &ValidationResponse{
				IsValid: true,
				Error:   nil,
			}, nil
		}

		errorType := getErrorType(err)
		return &ValidationResponse{
			IsValid: false,
			Error: &Error{
				Type:    errorType,
				Message: "Failed validating AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}

	return &ValidationResponse{
		IsValid: true,
		Error:   nil,
	}, nil
}
