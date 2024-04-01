// Thanks to okemechris on GitHub for the sample code. 
// See: https://github.com/okemechris/simplego-api/tree/main

package services

import (
    "encoding/json"
    "net/http"
    "github.com/OCP-on-NERC/prom-keycloak-proxy/src/errors"
)

func PromQuery(w http.ResponseWriter, r *http.Request) {
    data := new(errors.HttpError)
    json.NewEncoder(w).Encode(&data)
}
