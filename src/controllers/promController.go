// Thanks to okemechris on GitHub for the sample code. 
// See: https://github.com/okemechris/simplego-api/tree/main

package controllers
import (
    "net/http"
    "github.com/OCP-on-NERC/prom-keycloak-proxy/src/services"
    "github.com/gorilla/mux"
    "github.com/Nerzal/gocloak/v13"
)
type PromController struct {}
func (t PromController) RegisterRoutes(client *gocloak.GoCloak, router *mux.Router) {
    router.Handle("/api/v1/query",   services.Protect(client, http.HandlerFunc(services.PromQuery))).Methods("GET")
}
