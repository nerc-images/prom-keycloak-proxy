// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package services

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/errors"

	"github.com/Nerzal/gocloak/v13"
	_ "github.com/gorilla/mux"
)

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
}

var (
	clientId            = os.Getenv("AUTH_CLIENT_ID")
	clientSecret        = os.Getenv("AUTH_CLIENT_SECRET")
	realm               = os.Getenv("AUTH_REALM")
	auth_base_url       = os.Getenv("AUTH_BASE_URL")
	auth_skip_verify, _ = strconv.ParseBool(os.Getenv("AUTH_SKIP_VERIFY"))
)

func InitializeOauthServer() *gocloak.GoCloak {
	client := gocloak.NewClient(auth_base_url)
	if auth_skip_verify {
		restyClient := client.RestyClient()
		restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}
	return client
}

func Protect(client *gocloak.GoCloak, next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")

		if len(authHeader) < 1 {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.UnauthorizedError())
			return
		}

		accessToken := strings.Split(authHeader, " ")[1]

		rptResult, err := client.RetrospectToken(r.Context(), accessToken, clientId, clientSecret, realm)

		if err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error()))
			return
		}

		isTokenValid := *rptResult.Active

		if !isTokenValid {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.UnauthorizedError())
			return
		}
		rpp, err := client.GetRequestingPartyPermissions(
			context.Background(),
			accessToken,
			realm,
			gocloak.RequestingPartyTokenOptions{
				Audience: gocloak.StringP(clientId),
				Permissions: &[]string{
					"cluster#nerc-ocp-prod",
					"namespace#all namespaces",
				},
			},
		)
		if err != nil {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.UnauthorizedError())
			return
		}
		out, err := json.Marshal(*rpp)
		if err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error()))
			return
		}
		fmt.Print(string(out))

		// Our middleware logic goes here...
		next.ServeHTTP(w, r)
	})
}
