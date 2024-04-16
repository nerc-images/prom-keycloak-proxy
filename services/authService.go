// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package services

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/errors"
	"github.com/OCP-on-NERC/prom-keycloak-proxy/queries"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/Nerzal/gocloak/v13"
	_ "github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
}

func InitializeOauthServer(authBaseUrl string, authTlsVerify bool) *gocloak.GoCloak {
	client := gocloak.NewClient(authBaseUrl)
	if !authTlsVerify {
		restyClient := client.RestyClient()
		restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: !authTlsVerify})
	}
	return client
}

func Protect(gocloakClient *gocloak.GoCloak, authRealm string, authClientId string, authClientSecret string, next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get(queries.QueryParam)

		authHeader := r.Header.Get("Authorization")

		if len(authHeader) < 1 {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.UnauthorizedError())
			return
		}

		accessToken := strings.Split(authHeader, " ")[1]

		rptResult, err := gocloakClient.RetrospectToken(r.Context(), accessToken, authClientId, authClientSecret, authRealm)

		if err != nil {
			log.Warn().
				Int("status", 401).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("client-id", authClientId).
				Str("query", query).
				Msg("Unauthorized")

			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error()))
			return
		}

		isTokenValid := *rptResult.Active

		if !isTokenValid {
			log.Warn().
				Int("status", 401).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("client-id", authClientId).
				Str("query", query).
				Msg("Unauthorized")

			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.UnauthorizedError())
			return
		}

		queryValues := r.URL.Query()
		queryValuesForAuth := queries.ParseAuthorizations(queryValues)
		matchers := queryValuesForAuth[queries.QueryParam]
		var permissions []string

		// Inject label into existing matchers.
		for _, matcher := range matchers {
			matcherSelector, _ := parser.ParseMetricSelector(matcher)

			for _, matcherSelector := range matcherSelector {
				permissions = append(permissions, matcherSelector.Name+"#"+matcherSelector.Value)
			}
		}

		rpp, err := gocloakClient.GetRequestingPartyPermissions(
			context.Background(),
			accessToken,
			authRealm,
			gocloak.RequestingPartyTokenOptions{
				Audience:    gocloak.StringP(authClientId),
				Permissions: &permissions,
			},
		)

		if err != nil || len(*rpp) < 2 {
			log.Warn().
				Int("status", 403).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("client-id", authClientId).
				Str("query", query).
				Msg("Forbidden")

			w.WriteHeader(403)
			json.NewEncoder(w).Encode(errors.UnauthorizedError())
			return
		}

		out, err := json.Marshal(*rpp)
		if err != nil {
			log.Warn().
				Int("status", 400).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("client-id", authClientId).
				Str("query", query).
				Msg("Bad Request")

			w.WriteHeader(400)
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error()))
			return
		}

		log.Info().
			Int("status", 200).
			Str("method", r.Method).
			Str("path", r.RequestURI).
			Str("ip", r.RemoteAddr).
			Str("client-id", authClientId).
			Str("query", query).
			RawJSON("permissions", out).
			Msg("OK")

		// Our middleware logic goes here...
		next.ServeHTTP(w, r)
	})
}
