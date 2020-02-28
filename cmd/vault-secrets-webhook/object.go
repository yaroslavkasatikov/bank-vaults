// Copyright © 2020 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/base64"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	internal "github.com/banzaicloud/bank-vaults/internal/configuration"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

func traverseObject(o interface{}, vaultClient *vault.Client) error {
	switch value := o.(type) {
	case []interface{}:
		for i, v := range value {
			switch s := v.(type) {
			case string:
				if decoded, err := base64.StdEncoding.DecodeString(s); err != nil {
					s = string(decoded)
				}

				if hasVaultPrefix(s) {
					dataFromVault, err := getDataFromVault(map[string]string{"data": s}, vaultClient)
					if err != nil {
						return err
					}
					value[i] = dataFromVault["data"]
				}
			case map[string]interface{}, []interface{}:
				err := traverseObject(v, vaultClient)
				if err != nil {
					return err
				}
			}
		}
	case map[string]interface{}:
		for k, v := range value {
			switch s := v.(type) {
			case string:
				if decoded, err := base64.StdEncoding.DecodeString(s); err != nil {
					s = string(decoded)
				}

				if hasVaultPrefix(s) {
					dataFromVault, err := getDataFromVault(map[string]string{"data": s}, vaultClient)
					if err != nil {
						return err
					}
					value[k] = dataFromVault["data"]
				}
			case map[string]interface{}, []interface{}:
				err := traverseObject(v, vaultClient)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func mutateObject(object *unstructured.Unstructured, vaultConfig internal.VaultConfig) error {
	logger.Infof("mutating object: %s.%s", object.GetNamespace(), object.GetName())

	vaultClient, err := newVaultClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %v", err)
	}

	defer vaultClient.Close()

	return traverseObject(object.Object, vaultClient)
}
