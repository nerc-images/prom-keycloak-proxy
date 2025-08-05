// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package services

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/errors"
	"github.com/OCP-on-NERC/prom-keycloak-proxy/queries"

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

func Protect(hubKey string, clusterKey string, projectKey string, gocloakClient *gocloak.GoCloak, authRealm string, authClientId string, authClientSecret string, proxyAcmHub string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get(queries.QueryParam)

		authHeader := r.Header.Get("Authorization")

		if len(authHeader) < 1 {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.UnauthorizedError()) //nolint:errcheck
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
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error())) //nolint:errcheck
			return
		}

		userInfo, err := gocloakClient.GetUserInfo(context.Background(), accessToken, authRealm)
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
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error())) //nolint:errcheck
			return
		}
		username := *userInfo.PreferredUsername
		var userClientId = ""
		if strings.Contains(username, "service-account-") {
			userClientId = strings.ReplaceAll(username, "service-account-", "")
		}

		isTokenValid := *rptResult.Active

		if !isTokenValid {
			log.Warn().
				Int("status", 401).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("username", username).
				Str("client-id", userClientId).
				Str("query", query).
				Msg("Unauthorized")

			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.UnauthorizedError()) //nolint:errcheck
			return
		}

		queryValues := r.URL.Query()
		_, authResourceNames, authResourceScopes := queries.ParseAuthorizations(hubKey, clusterKey, projectKey, proxyAcmHub, queryValues)
		var permissions []string

		for index, authResourceName := range authResourceNames {
			authScopeName := authResourceScopes[index]
			permissions = append(permissions, fmt.Sprintf("%s#%s", authResourceName, authScopeName))
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

		if err != nil {
			log.Warn().
				Int("status", 403).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("username", username).
				Str("client-id", userClientId).
				Str("query", query).
				Msg(err.Error())

			w.WriteHeader(403)
			json.NewEncoder(w).Encode(errors.UnauthorizedError()) //nolint:errcheck
			return
		}

		out, err := json.Marshal(*rpp)
		if err != nil {
			log.Warn().
				Int("status", 400).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("username", username).
				Str("client-id", userClientId).
				Str("query", query).
				Msg("Bad Request")

			w.WriteHeader(400)
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error())) //nolint:errcheck
			return
		}

		var final_result = true
		var unauthorized_key = ""
		var unauthorized_value = ""
		var current_result = false
		for i, key := range authResourceNames {
			value := authResourceScopes[i]
			for _, permission := range *rpp {
				if key == *permission.ResourceName && slices.Contains(*permission.Scopes, value) {
					current_result = true
					break
				}
			}
			if !current_result {
				unauthorized_key = key
				unauthorized_value = value
			}
		}
		if !current_result {
			final_result = false
		}

		if final_result {
			log.Info().
				Int("status", 200).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("username", username).
				Str("client-id", userClientId).
				Str("query", query).
				RawJSON("permissions", out).
				Msg("OK")
		} else {
			message := "You are not authorized to access the resource \"" + unauthorized_key + "\" with scope \"" + unauthorized_value + "\""
			log.Warn().
				Int("status", 403).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("username", username).
				Str("client-id", userClientId).
				Str("query", query).
				Msg(message)

			w.WriteHeader(403)
			json.NewEncoder(w).Encode(errors.HttpError{Code: 403, Error: "Forbidden", Message: message}) //nolint:errcheck
			return
		}

		// Our middleware logic goes here...
		next.ServeHTTP(w, r)
	})
}
