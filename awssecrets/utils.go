package awssecrets

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"strings"
)

const (
	DefaultBasePath = "harness"
	PathSeparator   = "/"
)

// isValidJSON checks if a string is valid JSON
func isValidJSON(input string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(input), &js) == nil
}

// getValueFromJSON retrieves the value associated with a key from a JSON string
func getValueFromJSON(input string, key string) string {
	var result map[string]interface{}

	if err := json.Unmarshal([]byte(input), &result); err != nil {
		// Return original input if parsing fails
		return input
	}

	if key == "" {
		valueBytes, _ := json.Marshal(result)
		return string(valueBytes)
	}

	// Handle keys with dots in them by using nested lookups
	parts := strings.Split(key, ".")
	for _, part := range parts {
		if val, exists := result[part]; exists {
			if nestedMap, ok := val.(map[string]interface{}); ok {
				result = nestedMap
			} else {
				return fmt.Sprintf("%v", val)
			}
		} else {
			// Key not found
			return ""
		}
	}

	valBytes, _ := json.Marshal(result)
	return string(valBytes)
}

// extractSecretInfo determines the secret name and key from the given record
func extractSecretInfo(path string) (name string, key string) {
	if path != "" {
		parts := strings.SplitN(path, "#", 2)
		if len(parts) > 1 {
			return parts[0], parts[1]
		}
		return parts[0], ""
	}
	return "", ""
}

// decode does a base64 decode of the given string
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

func getFullPath(basePath, secretPath string) string {
	if basePath = strings.TrimSpace(basePath); basePath == "" {
		return DefaultBasePath + PathSeparator + secretPath
	}

	basePath = strings.Trim(basePath, PathSeparator)
	return basePath + PathSeparator + secretPath
}

func getFullPathWithoutStrippingPrefixSlash(basePath, secretPath string) string {
	basePath = strings.TrimRight(basePath, PathSeparator)
	return basePath + PathSeparator + secretPath
}
