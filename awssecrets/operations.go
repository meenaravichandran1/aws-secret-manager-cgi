package awssecrets

import (
	"aws-secret-manager-cgi/common"
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/sirupsen/logrus"
)

type AWSSecretManager struct {
	client *secretsmanager.Client
	config common.SecretManagerConfig
}

func New(config common.SecretManagerConfig) (common.SecretManager, error) {
	client, err := createAWSClient(config)
	if err != nil {
		return nil, err
	}
	return &AWSSecretManager{client: client, config: config}, nil
}

func (sm *AWSSecretManager) Connect(ctx context.Context, name string) (*common.ValidationResponse, error) {
	logrus.Infof("Received request for validating AWS Secret Manager: %s", name)
	_, err := getSecret(ctx, sm.client, name)
	if err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			logrus.Info("Successfully validated AWS Secret Manager")
			return &common.ValidationResponse{
				IsValid: true,
				Error:   nil,
			}, nil
		}

		errorType := getErrorType(err)
		logrus.Errorf("Failed to validate AWS Secret Manager, error %v", err.Error())
		return &common.ValidationResponse{
			IsValid: false,
			Error: &common.Error{
				Type:    errorType,
				Message: "Failed validating AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Info("Successfully validated AWS Secret Manager")
	return &common.ValidationResponse{
		IsValid: true,
		Error:   nil,
	}, nil
}

func (sm *AWSSecretManager) FetchSecret(ctx context.Context, secret common.Secret) (*common.SecretResponse, error) {
	logrus.Infof("Received request for fetching AWS Secret: %s", secret.Name)
	secretName, jsonKey := extractSecretInfo(secret.Name)

	secretOutput, err := getSecret(ctx, sm.client, secretName)
	if err != nil {
		logrus.Errorf("Failed to fetch secret %s, error: %v", secretName, err.Error())
		return nil, fmt.Errorf("could not find secret key: %s. Failed with error %v", secretName, err.Error())
	}
	logrus.Infof("Successfully fetched secret %s", secretName)
	secretValue := *secretOutput.SecretString

	decodedSecretValue, err := decode(secretValue, secret.Base64, secretName)
	if !isValidJSON(decodedSecretValue) {
		return &common.SecretResponse{
			Value: decodedSecretValue,
		}, nil
	}
	valueOfKey := getValueFromJSON(decodedSecretValue, jsonKey)
	return &common.SecretResponse{
		Value: valueOfKey,
	}, nil
}

func (sm *AWSSecretManager) CreateSecret(ctx context.Context, secret common.Secret) (*common.OperationResponse, error) {
	fullSecretName := getFullPath(sm.config.Prefix, secret.Name)
	secret.Name = fullSecretName

	logrus.Infof("Received request for creating AWS Secret: %s", fullSecretName)
	output, err := createSecret(ctx, sm.client, secret)
	if err != nil {
		logrus.Errorf("Failed to create secret %s, error: %v", fullSecretName, err.Error())
		return &common.OperationResponse{
			Name:            fullSecretName,
			Message:         "Failed to create secret in AWS Secret Manager",
			OperationStatus: common.OperationStatusFailure,
			Error: &common.Error{
				Message: "Failed to create secret in AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}

	logrus.Infof("Successfully created secret %s", fullSecretName)
	return &common.OperationResponse{
		Name:            *output.Name,
		Message:         "Successfully created secret in AWS Secret Manager",
		OperationStatus: common.OperationStatusSuccess,
		Error:           nil,
	}, nil
}

func (sm *AWSSecretManager) UpdateSecret(ctx context.Context, secret common.Secret) (*common.OperationResponse, error) {
	fullSecretName := getFullPath(sm.config.Prefix, secret.Name)
	secret.Name = fullSecretName

	logrus.Infof("Received request for updating AWS Secret: %s", fullSecretName)
	output, err := updateSecret(ctx, sm.client, secret)
	if err != nil {
		logrus.Errorf("Failed to update secret %s, error: %v", fullSecretName, err.Error())
		return &common.OperationResponse{
			Name:            fullSecretName,
			Message:         "Failed to update secret in AWS Secret Manager",
			OperationStatus: common.OperationStatusFailure,
			Error: &common.Error{
				Message: "Failed to update secret in AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}

	logrus.Infof("Successfully updated secret %s", fullSecretName)
	return &common.OperationResponse{
		Name:            *output.Name,
		Message:         "Successfully updated secret in AWS Secret Manager",
		OperationStatus: common.OperationStatusSuccess,
		Error:           nil,
	}, nil
}

func (sm *AWSSecretManager) UpsertSecret(ctx context.Context, secret common.Secret, existingSecret *common.Secret) (*common.OperationResponse, error) {
	fullSecretName := getFullPath(sm.config.Prefix, secret.Name)
	secretExists := false

	if _, err := fetchSecretInternal(ctx, sm.client, fullSecretName); err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			logrus.Infof("Resource %s Doesn't exist : %v", fullSecretName, err.Error())
		} else {
			logrus.Warnf("Failed fetching secret %s, error : %v, retrying...", fullSecretName, err.Error())
			
			// for ticket https://harness.atlassian.net/browse/PL-39194
			fullSecretName = getFullPathWithoutStrippingPrefixSlash(sm.config.Prefix, secret.Name)
			if _, err := fetchSecretInternal(ctx, sm.client, fullSecretName); err != nil {
				if errors.As(err, &resourceNotFoundErr) {
					logrus.Infof("Resource %s Doesn't exist : %v", fullSecretName, err.Error())
				} else {
					logrus.Errorf("Failed fetching secret %s, error : %v", fullSecretName, err.Error())
					return &common.OperationResponse{
						Name:            fullSecretName,
						Message:         "Failed to find secret in AWS Secret Manager",
						OperationStatus: common.OperationStatusFailure,
						Error: &common.Error{
							Message: "Failed to find secret in AWS Secret Manager",
							Reason:  err.Error(),
						},
					}, nil
				}
			}
		}
	} else {
		secretExists = true
	}

	var err error
	var response *common.OperationResponse
	if !secretExists {
		response, err = sm.CreateSecret(ctx, secret)
	} else {
		response, err = sm.UpdateSecret(ctx, secret)
	}
	if err != nil {
		return nil, err
	}

	if existingSecret != nil {
		oldFullSecretName := existingSecret.Name
		logrus.Debugf("Old secret name is %s", oldFullSecretName)
		logrus.Debugf("New secret name is %s", fullSecretName)

		if oldFullSecretName != "" && oldFullSecretName != fullSecretName {
			logrus.Infof("Old path of the secret %s is different than the current one %s. Deleting the old secret",
				oldFullSecretName, fullSecretName)
			if _, err := deleteSecret(ctx, sm.client, *existingSecret); err != nil {
				logrus.Warnf("Old path of the secret %s is different than the current one %s. Failed deleting the old secret. Error: %v",
					oldFullSecretName, fullSecretName, err.Error())
			}
		}
	}
	return response, nil
}

func (sm *AWSSecretManager) RenameSecret(ctx context.Context, secret common.Secret, existingSecret *common.Secret) (*common.OperationResponse, error) {
	fullSecretName := getFullPath(sm.config.Prefix, secret.Name)
	logrus.Infof("Received request for renaming AWS Secret: %s", fullSecretName)
	//fetch existing record - if not found, nothing to update because we won't know what value to update
	secretValue, err := fetchSecretInternal(ctx, sm.client, existingSecret.Name)
	if err != nil {
		return &common.OperationResponse{
			Name:            existingSecret.Name,
			Message:         "Failed to find secret in AWS Secret Manager",
			OperationStatus: common.OperationStatusFailure,
			Error: &common.Error{
				Message: "Failed to find secret in AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}

	secret.Plaintext = &secretValue
	// upsert with new secret
	return sm.UpsertSecret(ctx, secret, existingSecret)
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

func (sm *AWSSecretManager) ValidateReference(ctx context.Context, name string) (*common.ValidationResponse, error) {
	logrus.Infof("Received request for validating AWS Secret reference: %s", name)
	_, err := fetchSecretInternal(ctx, sm.client, name)

	if err != nil {
		logrus.Errorf("Failed to validate AWS Secret reference, error %v", err.Error())
		return &common.ValidationResponse{
			IsValid: false,
			Error: &common.Error{
				Message: "Failed validating AWS Secret reference",
				Reason:  err.Error(),
			},
		}, nil
	}
	logrus.Info("Successfully validated AWS Secret reference")
	return &common.ValidationResponse{
		IsValid: true,
		Error:   nil,
	}, nil
}

func (sm *AWSSecretManager) DeleteSecret(ctx context.Context, secret common.Secret) (*common.OperationResponse, error) {
	secretName := secret.Name
	logrus.Infof("Received request for deleting AWS Secret: %s", secretName)
	output, err := deleteSecret(ctx, sm.client, secret)
	if err != nil {
		logrus.Errorf("Failed to delete secret %s, error: %v", secretName, err.Error())
		return &common.OperationResponse{
			Name:            secretName,
			Message:         "Failed to delete secret in AWS Secret Manager",
			OperationStatus: common.OperationStatusFailure,
			Error: &common.Error{
				Message: "Failed to delete secret in AWS Secret Manager",
				Reason:  err.Error(),
			},
		}, nil
	}

	logrus.Infof("Successfully deleted secret %s", secretName)
	return &common.OperationResponse{
		Name:            *output.Name,
		Message:         "Successfully deleted secret in AWS Secret Manager",
		OperationStatus: common.OperationStatusSuccess,
		Error:           nil,
	}, nil
}
