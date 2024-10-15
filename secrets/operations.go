package secrets

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/sirupsen/logrus"
)

func HandleConnect(ctx context.Context, client *secretsmanager.Client, name *string) (*ValidationResponse, error) {
	logrus.Infof("Received request for validating AWS Secret Manager: %s", *name)
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

func HandleFetch(ctx context.Context, client *secretsmanager.Client, name string, storeConfig *SecretManagerConfig) (*SecretResponse, error) {
	logrus.Infof("Received request for fetching AWS Secret: %s", name)
	//name = GetFullPath(storeConfig.Prefix, name)
	// TODO get the name here instead of cg-manager for uniformity - wrong get the name in cg-manager for uniformity
	secretName, jsonKey := extractSecretInfo(name)
	secretOutput, err := getSecret(ctx, client, &secretName)
	if err != nil {
		logrus.Errorf("Failed to fetch secret %s, error: %v", name, err.Error())
		return nil, fmt.Errorf("could not find secret key: %s. Failed with error %v", secretName, err.Error())
	}
	logrus.Infof("Successfully fetched secret %s", name)
	secretValue := *secretOutput.SecretString
	if !isValidJSON(secretValue) {
		return &SecretResponse{
			Value: secretValue,
		}, nil
	}
	valueOfKey := getValueFromJSON(secretValue, jsonKey)
	return &SecretResponse{
		Value: valueOfKey,
	}, nil
}

func Create(ctx context.Context, client *secretsmanager.Client, secret *Secret) (*OperationResponse, error) {
	logrus.Infof("Received request for creating AWS Secret: %s", *secret.Name)
	output, err := createSecret(ctx, client, secret)
	if err != nil {
		errorType := getErrorType(err)
		logrus.Errorf("Failed to create secret %s, errorType: %s, error: %v", *secret.Name, errorType, err.Error())
		return &OperationResponse{
			Name:            *secret.Name,
			Message:         "Failed to create secret in AWS Secret Manager",
			OperationStatus: OperationStatusFailure,
			Error: &Error{
				Message: "Failed to create secret in AWS Secret Manager",
				Type:    errorType,
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Infof("Successfully created secret %s", *secret.Name)
	return &OperationResponse{
		Name:            *output.Name,
		Message:         "Successfully created secret in AWS Secret Manager",
		OperationStatus: OperationStatusSuccess,
		Error:           nil,
	}, nil
}

func Update(ctx context.Context, client *secretsmanager.Client, secret *Secret) (*OperationResponse, error) {
	logrus.Infof("Received request for updating AWS Secret: %s", *secret.Name)
	output, err := updateSecret(ctx, client, secret)
	if err != nil {
		errorType := getErrorType(err)
		logrus.Errorf("Failed to update secret %s, errorType: %s, error: %v", *secret.Name, errorType, err.Error())
		return &OperationResponse{
			Name:            *secret.Name,
			Message:         "Failed to update secret in AWS Secret Manager",
			OperationStatus: OperationStatusFailure,
			Error: &Error{
				Message: "Failed to update secret in AWS Secret Manager",
				Type:    errorType,
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Infof("Successfully updated secret %s", *secret.Name)
	return &OperationResponse{
		Name:            *output.Name,
		Message:         "Successfully updated secret in AWS Secret Manager",
		OperationStatus: OperationStatusSuccess,
		Error:           nil,
	}, nil
}

func HandleUpsert(ctx context.Context, client *secretsmanager.Client, secret *Secret, existingSecret *Secret, storeConfig *SecretManagerConfig) (*OperationResponse, error) {
	//fullSecretName := GetFullPath(storeConfig.Prefix, *secret.Name)
	//secret.Name = &fullSecretName
	secretExists := false
	if _, err := fetchSecretInternal(ctx, client, *secret.Name); err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			logrus.Infof("Resource %s Doesn't exist : %v", *secret.Name, err.Error())
		} else {
			logrus.Errorf("Failed fetching secret %s, error : %v", *secret.Name, err.Error())
			// TODO send error because failed with some other error like auth failed
			errorType := getErrorType(err)
			return &OperationResponse{
				Name:            *existingSecret.Name,
				Message:         "Failed to find secret in AWS Secret Manager",
				OperationStatus: OperationStatusFailure,
				Error: &Error{
					Message: "Failed to find secret in AWS Secret Manager",
					Type:    errorType,
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
		response, err = Create(ctx, client, secret)
	} else {
		response, err = Update(ctx, client, secret)
	}
	if err != nil {
		return nil, err
	}

	// TODO send this from manager
	if existingSecret != nil {
		//existingSecretName := GetFullPath(storeConfig.Prefix, *existingSecret.Name)
		//existingSecret.Name = &existingSecretName
		oldFullSecretName := *existingSecret.Name
		logrus.Infof("Old secret name is %s", oldFullSecretName)
		logrus.Infof("New secret name is %s", *secret.Name)
		if oldFullSecretName != "" && oldFullSecretName != *secret.Name {
			logrus.Infof("Old path of the secret %s is different than the current one %s. Deleting the old secret",
				oldFullSecretName, *secret.Name)
			if _, err := deleteSecret(ctx, client, existingSecret); err != nil {
				logrus.Warnf("Old path of the secret %s is different than the current one %s. Failed deleting the old secret. Error: %v",
					oldFullSecretName, *secret.Name, err.Error())
			}
		}
	}
	return response, nil
}

func HandleRename(ctx context.Context, client *secretsmanager.Client, secret *Secret, existingSecret *Secret, storeConfig *SecretManagerConfig) (*OperationResponse, error) {
	logrus.Infof("Received request for renaming AWS Secret: %s", *secret.Name)
	//fetch existing record - if not found, nothing to update because we won't know what value to update
	//existingSecretName := GetFullPath(storeConfig.Prefix, *existingSecret.Name)
	secretValue, err := fetchSecretInternal(ctx, client, *existingSecret.Name)
	if err != nil {
		errorType := getErrorType(err)
		return &OperationResponse{
			Name:            *existingSecret.Name,
			Message:         "Failed to find secret in AWS Secret Manager",
			OperationStatus: OperationStatusFailure,
			Error: &Error{
				Message: "Failed to find secret in AWS Secret Manager",
				Type:    errorType,
				Reason:  err.Error(),
			},
		}, nil
	}
	secret.Plaintext = &secretValue
	// upsert with new secret
	return HandleUpsert(ctx, client, secret, existingSecret, storeConfig)
}

// TODO rename and rewrite especially the json stuff
func fetchSecretInternal(ctx context.Context, client *secretsmanager.Client, name string) (string, error) {

	secretName, jsonKey := extractSecretInfo(name)
	secretOutput, err := getSecret(ctx, client, &secretName)
	if err != nil {
		return "", err
	}
	secretValue := *secretOutput.SecretString
	if !isValidJSON(secretValue) {
		return secretValue, nil
	}
	return getValueFromJSON(secretValue, jsonKey), nil
}

func HandleDelete(ctx context.Context, client *secretsmanager.Client, secret *Secret, storeConfig *SecretManagerConfig) (*OperationResponse, error) {
	logrus.Infof("Received request for deleting AWS Secret: %s", *secret.Name)
	//fullSecretName := GetFullPath(storeConfig.Prefix, *secret.Name)
	//secret.Name = &fullSecretName
	output, err := deleteSecret(ctx, client, secret)
	if err != nil {
		errorType := getErrorType(err)
		logrus.Errorf("Failed to delete secret %s, errorType: %s, error: %v", *secret.Name, errorType, err.Error())
		return &OperationResponse{
			Name:            *secret.Name,
			Message:         "Failed to delete secret in AWS Secret Manager",
			OperationStatus: OperationStatusFailure,
			Error: &Error{
				Message: "Failed to delete secret in AWS Secret Manager",
				Type:    errorType,
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Infof("Successfully deleted secret %s", *secret.Name)
	return &OperationResponse{
		Name:            *output.Name,
		Message:         "Successfully deleted secret in AWS Secret Manager",
		OperationStatus: OperationStatusSuccess,
		Error:           nil,
	}, nil
}
