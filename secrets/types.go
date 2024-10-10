package secrets

type input struct {
	SecretParams *SecretParams `json:"secret_params"`
}

type SecretParams struct {
	Action string               `json:"secret_operation"`
	Config *SecretManagerConfig `json:"store_config"`
	Secret *Secret              `json:"secret"`
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
}

type Secret struct {
	Name *string `json:"name"`
}

type ValidationResponse struct {
	IsValid bool   `json:"valid"`
	Error   *Error `json:"error"`
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
