package secrets

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func New(storeConfig SecretManagerConfig) (*secretsmanager.Client, error) {
	if storeConfig.AccessKey == "" {
		return nil, fmt.Errorf("AccessKey not provided")
	}
	if storeConfig.SecretKey == "" {
		return nil, fmt.Errorf("SecretKey not provided")
	}

	region := "us-east-1"
	if storeConfig.Region != "" {
		region = storeConfig.Region
	}

	staticCredentialsProvider := credentials.NewStaticCredentialsProvider(storeConfig.AccessKey, storeConfig.SecretKey, "")

	awsConfig, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(staticCredentialsProvider),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	return secretsmanager.NewFromConfig(awsConfig), nil
}
