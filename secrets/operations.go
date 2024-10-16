package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/sirupsen/logrus"
)

func HandleConnect(ctx context.Context, client *secretsmanager.Client, name string) (*ValidationResponse, error) {
	logrus.Infof("Received request for validating AWS Secret Manager: %s", name)
	_, err := getSecret(ctx, client, name)
	if err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			logrus.Info("Successfully validated AWS Secret Manager")
			return &ValidationResponse{
				IsValid: true,
				Error:   nil,
			}, nil
		}

		errorType := getErrorType(err)
		logrus.Errorf("Failed to validate AWS Secret Manager, error %v", err.Error())
		return &ValidationResponse{
			IsValid: false,
			Error: &Error{
				Type:    errorType,
				Message: "Failed validating AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Info("Successfully validated AWS Secret Manager")
	return &ValidationResponse{
		IsValid: true,
		Error:   nil,
	}, nil
}

func HandleFetch(ctx context.Context, client *secretsmanager.Client, secret Secret) (*SecretResponse, error) {
	logrus.Infof("Received request for fetching AWS Secret: %s", secret.Name)
	secretName, jsonKey := extractSecretInfo(secret.Name)
	secretOutput, err := getSecret(ctx, client, secretName)
	if err != nil {
		logrus.Errorf("Failed to fetch secret %s, error: %v", secretName, err.Error())
		return nil, fmt.Errorf("could not find secret key: %s. Failed with error %v", secretName, err.Error())
	}
	logrus.Infof("Successfully fetched secret %s", secretName)
	secretValue := *secretOutput.SecretString

	decodedSecretValue, err := decode(secretValue, secret.Base64, secretName)
	if !isValidJSON(decodedSecretValue) {
		return &SecretResponse{
			Value: decodedSecretValue,
		}, nil
	}
	valueOfKey := getValueFromJSON(decodedSecretValue, jsonKey)
	return &SecretResponse{
		Value: valueOfKey,
	}, nil
}

func decode(s string, decode bool, name string) (string, error) {
	if decode {
		logrus.Infof("Decoding secret %s", name)
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", fmt.Errorf("error occurred when decoding base64 secret: %s. Failed with error %v", name, err.Error())
		}
		return string(decoded), nil
	}
	return s, nil
}

func HandleCreate(ctx context.Context, client *secretsmanager.Client, secret Secret) (*OperationResponse, error) {
	secretName := secret.Name
	logrus.Infof("Received request for creating AWS Secret: %s", secretName)
	output, err := createSecret(ctx, client, secret)
	if err != nil {
		logrus.Errorf("Failed to create secret %s, error: %v", secretName, err.Error())
		return &OperationResponse{
			Name:            secretName,
			Message:         "Failed to create secret in AWS Secret Manager",
			OperationStatus: OperationStatusFailure,
			Error: &Error{
				Message: "Failed to create secret in AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Infof("Successfully created secret %s", secretName)
	return &OperationResponse{
		Name:            *output.Name,
		Message:         "Successfully created secret in AWS Secret Manager",
		OperationStatus: OperationStatusSuccess,
		Error:           nil,
	}, nil
}

func Update(ctx context.Context, client *secretsmanager.Client, secret Secret) (*OperationResponse, error) {
	secretName := secret.Name
	logrus.Infof("Received request for updating AWS Secret: %s", secretName)
	output, err := updateSecret(ctx, client, secret)
	if err != nil {
		logrus.Errorf("Failed to update secret %s, error: %v", secretName, err.Error())
		return &OperationResponse{
			Name:            secretName,
			Message:         "Failed to update secret in AWS Secret Manager",
			OperationStatus: OperationStatusFailure,
			Error: &Error{
				Message: "Failed to update secret in AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Infof("Successfully updated secret %s", secretName)
	return &OperationResponse{
		Name:            *output.Name,
		Message:         "Successfully updated secret in AWS Secret Manager",
		OperationStatus: OperationStatusSuccess,
		Error:           nil,
	}, nil
}

func HandleUpsert(ctx context.Context, client *secretsmanager.Client, secret Secret, existingSecret *Secret) (*OperationResponse, error) {
	secretName := secret.Name
	secretExists := false
	if _, err := fetchSecretInternal(ctx, client, secretName); err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			logrus.Infof("Resource %s Doesn't exist : %v", secretName, err.Error())
		} else {
			logrus.Errorf("Failed fetching secret %s, error : %v", secretName, err.Error())
			return &OperationResponse{
				Name:            existingSecret.Name,
				Message:         "Failed to find secret in AWS Secret Manager",
				OperationStatus: OperationStatusFailure,
				Error: &Error{
					Message: "Failed to find secret in AWS Secret Manager",
					Reason:  err.Error(),
				},
			}, nil
		}
	} else {
		secretExists = true
	}

	var err error
	var response *OperationResponse
	if !secretExists {
		response, err = HandleCreate(ctx, client, secret)
	} else {
		response, err = Update(ctx, client, secret)
	}
	if err != nil {
		return nil, err
	}

	if existingSecret != nil {
		oldFullSecretName := existingSecret.Name
		logrus.Debugf("Old secret name is %s", oldFullSecretName)
		logrus.Debugf("New secret name is %s", secretName)
		if oldFullSecretName != "" && oldFullSecretName != secretName {
			logrus.Infof("Old path of the secret %s is different than the current one %s. Deleting the old secret",
				oldFullSecretName, secretName)
			if _, err := deleteSecret(ctx, client, *existingSecret); err != nil {
				logrus.Warnf("Old path of the secret %s is different than the current one %s. Failed deleting the old secret. Error: %v",
					oldFullSecretName, secretName, err.Error())
			}
		}
	}
	return response, nil
}

func HandleRename(ctx context.Context, client *secretsmanager.Client, secret Secret, existingSecret *Secret) (*OperationResponse, error) {
	logrus.Infof("Received request for renaming AWS Secret: %s", secret.Name)
	//fetch existing record - if not found, nothing to update because we won't know what value to update
	secretValue, err := fetchSecretInternal(ctx, client, existingSecret.Name)
	if err != nil {
		return &OperationResponse{
			Name:            existingSecret.Name,
			Message:         "Failed to find secret in AWS Secret Manager",
			OperationStatus: OperationStatusFailure,
			Error: &Error{
				Message: "Failed to find secret in AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}
	secret.Plaintext = &secretValue
	// upsert with new secret
	return HandleUpsert(ctx, client, secret, existingSecret)
}

func fetchSecretInternal(ctx context.Context, client *secretsmanager.Client, name string) (string, error) {
	secretName, jsonKey := extractSecretInfo(name)
	secretOutput, err := getSecret(ctx, client, secretName)
	if err != nil {
		return "", err
	}
	secretValue := *secretOutput.SecretString
	if !isValidJSON(secretValue) {
		return secretValue, nil
	}
	return getValueFromJSON(secretValue, jsonKey), nil
}

func HandleValidateRef(ctx context.Context, client *secretsmanager.Client, name string) (*ValidationResponse, error) {
	logrus.Infof("Received request for validating AWS Secret reference: %s", name)
	_, err := fetchSecretInternal(ctx, client, name)

	if err != nil {
		logrus.Errorf("Failed to validate AWS Secret reference, error %v", err.Error())
		return &ValidationResponse{
			IsValid: false,
			Error: &Error{
				Message: "Failed validating AWS Secret reference",
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Info("Successfully validated AWS Secret reference")
	return &ValidationResponse{
		IsValid: true,
		Error:   nil,
	}, nil
}

func HandleDelete(ctx context.Context, client *secretsmanager.Client, secret Secret) (*OperationResponse, error) {
	secretName := secret.Name
	logrus.Infof("Received request for deleting AWS Secret: %s", secretName)
	output, err := deleteSecret(ctx, client, secret)
	if err != nil {
		logrus.Errorf("Failed to delete secret %s, error: %v", secretName, err.Error())
		return &OperationResponse{
			Name:            secretName,
			Message:         "Failed to delete secret in AWS Secret Manager",
			OperationStatus: OperationStatusFailure,
			Error: &Error{
				Message: "Failed to delete secret in AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Infof("Successfully deleted secret %s", secretName)
	return &OperationResponse{
		Name:            *output.Name,
		Message:         "Successfully deleted secret in AWS Secret Manager",
		OperationStatus: OperationStatusSuccess,
		Error:           nil,
	}, nil
}
