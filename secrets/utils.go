package secrets

import (
	"encoding/json"
	"fmt"
	"strings"
)

// isValidJSON checks if a string is valid JSON.
func isValidJSON(input string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(input), &js) == nil
}

// getValueFromJSON retrieves the value associated with a key from a JSON string.
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

	// Handle keys with dots in them by using nested lookups.
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

// extractSecretInfo determines the secret name and key from the given record.
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
