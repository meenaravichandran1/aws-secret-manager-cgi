package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func fetchSecret(client *secretsmanager.Client, secretName string) (*secretsmanager.GetSecretValueOutput, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	}

	result, err := client.GetSecretValue(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	return result, nil
}
