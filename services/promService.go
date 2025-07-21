// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package services

import (
	"encoding/json"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
	"github.com/OCP-on-NERC/prom-keycloak-proxy/errors"
	"github.com/OCP-on-NERC/prom-keycloak-proxy/queries"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/rs/zerolog/log"
)

func PromQueryHandler(gocloakClient *gocloak.GoCloak, authRealm string, authClientId string, prometheusBaseUrl string, prometheusTlsCertPath string, prometheusTlsKeyPath string, prometheusCaCertPath string) http.HandlerFunc {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			queryValues := r.URL.Query()
			matchers := queryValues[queries.QueryParam]
			for _, matcher := range matchers {
				expr, _ := parser.ParseExpr(matcher)
				queryValues.Set(queries.QueryParam, expr.String())
			}
			prometheusUrl := prometheusBaseUrl + r.URL.Path + "?" + queryValues.Encode()

			data, err := queries.QueryPrometheus(prometheusTlsCertPath, prometheusTlsKeyPath, prometheusCaCertPath, prometheusUrl)
			if err == nil {
				json.NewEncoder(w).Encode(&data)
			} else {
				log.Err(err).
					Int("status", 200).
					Str("method", r.Method).
					Str("path", r.RequestURI).
					Str("ip", r.RemoteAddr).
					Str("client-id", authClientId).
					Str("query", r.URL.RawQuery).
					Msg("")
				data := new(errors.HttpError)
				json.NewEncoder(w).Encode(&data)
			}
		})
}
