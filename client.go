package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func newSecretsManagerClient(cfg SecretManagerConfig) (*secretsmanager.Client, error) {
	if cfg.AccessKey == "" {
		return nil, fmt.Errorf("you must provide an AccessKey")
	}
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("you must provide a SecretKey")
	}

	region := "us-east-1"
	if cfg.Region != "" {
		region = cfg.Region
	}

	creds := credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")

	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(creds),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	return secretsmanager.NewFromConfig(awsCfg), nil
}
