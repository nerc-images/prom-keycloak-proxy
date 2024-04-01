// Thanks to okemechris on GitHub for the sample code. 
// See: https://github.com/okemechris/simplego-api/tree/main

package main
import (
    "github.com/gorilla/mux"
    "github.com/Nerzal/gocloak/v13"
    "log"
    "net/http"
    controllers "github.com/OCP-on-NERC/prom-keycloak-proxy/src/controllers"
    services "github.com/OCP-on-NERC/prom-keycloak-proxy/src/services"
)
func main() {
    run()
}
func run() {
    client := services.InitializeOauthServer()
    router := mux.NewRouter().StrictSlash(true)
    router.Use(commonMiddleware)
    registerRoutes(client, router)
    log.Fatal(http.ListenAndServe(":8081", router))
}
func registerRoutes (client *gocloak.GoCloak, router *mux.Router){
    registerControllerRoutes(client, controllers.PromController{}, router)
}
func registerControllerRoutes(client *gocloak.GoCloak, controller controllers.Controller, router *mux.Router) {
    controller.RegisterRoutes(client, router)
}
func commonMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Add("Content-Type", "application/json")
        next.ServeHTTP(w, r)
    })
}
