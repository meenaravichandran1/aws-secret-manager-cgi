package secrets

type input struct {
	SecretParams *SecretParams `json:"secret_params"`
}

type SecretParams struct {
	Action         string               `json:"secret_operation"`
	Config         *SecretManagerConfig `json:"store_config"`
	Secret         *Secret              `json:"secret"`
	ExistingSecret *Secret              `json:"existing_secret"`
}

type SecretManagerConfig struct {
	Region                string `json:"region"`
	AccessKey             string `json:"access_key"`
	SecretKey             string `json:"secret_key"`
	AssumeIamRoleOnRunner bool   `json:"assume_iam_role"`
	AssumeStsRoleOnRunner bool   `json:"assume_sts_role"`
	AssumeStsRoleDuration int    `json:"assume_sts_role_duration"`
	RoleArn               string `json:"role_arn"`
	ExternalName          string `json:"external_name"`
	Prefix                string `json:"prefix,omitempty"`
}

type Secret struct {
	// from runner perspective, name is always fully qualified including the prefix, path, etc.
	Name      *string `json:"name"`
	Plaintext *string `json:"plaintext"`
}

type ValidationResponse struct {
	IsValid bool   `json:"valid"`
	Error   *Error `json:"error"`
}

type OperationStatus string

var (
	OperationStatusSuccess OperationStatus = "SUCCESS"
	OperationStatusFailure OperationStatus = "FAILURE"
)

type OperationResponse struct {
	Name            string          `json:"name"`
	Message         string          `json:"message"`
	Error           *Error          `json:"error"`
	OperationStatus OperationStatus `json:"status"`
}

type Error struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
}

type ErrorResponse struct {
	Message string `json:"message"`
	Error   string `json:"error"`
	Status  int    `json:"status"`
}

// SecretResponse for fetch secret tasks
type SecretResponse struct {
	Value string `json:"value"`
}
