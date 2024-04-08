// Thanks to okemechris on GitHub for the sample code. 
// See: https://github.com/okemechris/simplego-api/tree/main

package controllers

import (
    "github.com/gorilla/mux"
    "github.com/Nerzal/gocloak/v13"
)

type Controller interface {
    RegisterRoutes(client *gocloak.GoCloak, router *mux.Router)
}
