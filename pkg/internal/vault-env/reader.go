package reader

import (
	"fmt"
	"strings"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

type sanitizedEnviron map[string]string

// Appends variable an entry (name=value) into the environ list.
// VAULT_* variables are not populated into this list.
func (environ sanitizedEnviron) append(iname interface{}, ivalue interface{}) {
	name, value := iname.(string), ivalue.(string)
	if _, ok := sanitizeEnvmap[name]; !ok {
		environ[name] = value
	}
}

var sanitizeEnvmap = map[string]bool{
	"VAULT_TOKEN":                  true,
	"VAULT_ADDR":                   true,
	"VAULT_CACERT":                 true,
	"VAULT_CAPATH":                 true,
	"VAULT_CLIENT_CERT":            true,
	"VAULT_CLIENT_KEY":             true,
	"VAULT_CLIENT_TIMEOUT":         true,
	"VAULT_CLUSTER_ADDR":           true,
	"VAULT_MAX_RETRIES":            true,
	"VAULT_REDIRECT_ADDR":          true,
	"VAULT_SKIP_VERIFY":            true,
	"VAULT_TLS_SERVER_NAME":        true,
	"VAULT_CLI_NO_COLOR":           true,
	"VAULT_RATE_LIMIT":             true,
	"VAULT_NAMESPACE":              true,
	"VAULT_MFA":                    true,
	"VAULT_ROLE":                   true,
	"VAULT_PATH":                   true,
	"VAULT_IGNORE_MISSING_SECRETS": true,
}

// ReadFromVault reads a map of secrets from Vault
func ReadFromVault(client *vault.Client, environ map[string]string, ignoreMissingSecrets bool) (map[string]string, error) {

	sanitized := make(sanitizedEnviron, len(environ))

	for _, env := range environ {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]
		var update bool
		if strings.HasPrefix(value, ">>") {
			value = strings.TrimPrefix(value, ">>")
			update = true
		} else {
			update = false
		}
		if strings.HasPrefix(value, "vault:") {
			path := strings.TrimPrefix(value, "vault:")
			split := strings.SplitN(path, "#", 3)
			path = split[0]

			var key string
			if len(split) > 1 {
				key = split[1]
			}

			version := "-1"
			if len(split) == 3 {
				version = split[2]
			}

			var secret *vaultapi.Secret
			var err error

			if update {
				var empty map[string]interface{}
				secret, err = client.Vault().Logical().Write(path, empty)
				if err != nil {
					return nil, fmt.Errorf("failed to write secret %s: %s", path, err.Error())
				}
			} else {
				secret, err = client.Vault().Logical().ReadWithData(path, map[string][]string{"version": {version}})
				if err != nil {
					if ignoreMissingSecrets {
						logger.Warnf("failed to read secret %s: %s", path, err.Error())
					} else {
						return nil, fmt.Errorf("failed to read secret %s: %s", path, err.Error())
					}
				}
			}

			if secret == nil {
				if ignoreMissingSecrets {
					logger.Warnf("path not found: %s", path)
				} else {
					return nil, fmt.Errorf("path not found: %s", path)
				}
			} else {
				var data map[string]interface{}
				v2Data, ok := secret.Data["data"]
				if ok {
					data = cast.ToStringMap(v2Data)

					// Check if a given version of a path is destroyed
					metadata := secret.Data["metadata"].(map[string]interface{})
					if metadata["destroyed"].(bool) {
						logger.WithFields(logger.Fields{"version": version, "path": path}).Warn("Version of secret has been permanently destroyed")
					}

					// Check if a given version of a path still exists
					if metadata["deletion_time"].(string) != "" {
						logger.WithFields(logger.Fields{"path": path, "version": version, "deletion_time": metadata["deletion_time"]}).Warn("Cannot find data for path, given version has been deleted")
					}
				} else {
					data = cast.ToStringMap(secret.Data)
				}
				if value, ok := data[key]; ok {
					sanitized.append(name, value)
				} else {
					return nil, fmt.Errorf("key not found: %s", key)
				}
			}
		} else {
			sanitized.append(name, value)
		}
	}

	return sanitized, nil
}
