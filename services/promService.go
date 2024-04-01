// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package services

import (
	"encoding/json"
	"github.com/OCP-on-NERC/prom-keycloak-proxy/errors"
	"net/http"
)

func PromQuery(w http.ResponseWriter, r *http.Request) {
	data := new(errors.HttpError)
	json.NewEncoder(w).Encode(&data)
}
