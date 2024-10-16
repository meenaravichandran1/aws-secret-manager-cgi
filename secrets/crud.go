package secrets

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// getSecret fetches the secret value from AWS Secrets Manager
func getSecret(ctx context.Context, client *secretsmanager.Client, secretName string) (*secretsmanager.GetSecretValueOutput, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	output, err := client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// createSecret creates the secret value in AWS Secrets Manager
func createSecret(ctx context.Context, client *secretsmanager.Client, secret Secret) (*secretsmanager.CreateSecretOutput, error) {
	input := &secretsmanager.CreateSecretInput{
		Name:         aws.String(secret.Name),
		SecretString: secret.Plaintext,
		Tags: []types.Tag{{
			Key:   aws.String("createdBy"),
			Value: aws.String("Harness"),
		}},
	}

	output, err := client.CreateSecret(ctx, input)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// updateSecret updates the secret value in AWS Secrets Manager
func updateSecret(ctx context.Context, client *secretsmanager.Client, secret Secret) (*secretsmanager.UpdateSecretOutput, error) {
	input := &secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(secret.Name),
		SecretString: secret.Plaintext,
	}

	output, err := client.UpdateSecret(ctx, input)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// deleteSecret deletes the secret value in AWS Secrets Manager
func deleteSecret(ctx context.Context, client *secretsmanager.Client, secret Secret) (*secretsmanager.DeleteSecretOutput, error) {
	input := &secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(secret.Name),
		ForceDeleteWithoutRecovery: aws.Bool(true),
	}

	output, err := client.DeleteSecret(ctx, input)
	if err != nil {
		return nil, err
	}

	return output, nil
}
