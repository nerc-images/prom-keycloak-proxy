// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package services

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/Nerzal/gocloak/v13"
	"github.com/OCP-on-NERC/prom-keycloak-proxy/errors"
	"github.com/OCP-on-NERC/prom-keycloak-proxy/queries"
	"github.com/prometheus/prometheus/promql/parser"
)

func PromQueryHandler(gocloakClient *gocloak.GoCloak, authRealm string, authClientId string, prometheusBaseUrl string, prometheusTlsCertPath string, prometheusTlsKeyPath string, prometheusCaCertPath string) http.HandlerFunc {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			queryValues := r.URL.Query()
			matchers := queryValues[queries.QueryParam]
			v := make(url.Values)
			for _, matcher := range matchers {
				expr, _ := parser.ParseExpr(matcher)
				v.Set(queries.QueryParam, expr.String())
			}
			prometheusUrl := prometheusBaseUrl + r.URL.Path + "?" + v.Encode()

			data, err := queries.QueryPrometheus(prometheusTlsCertPath, prometheusTlsKeyPath, prometheusCaCertPath, prometheusUrl)
			if err == nil {
				json.NewEncoder(w).Encode(&data)
			} else {
				data := new(errors.HttpError)
				json.NewEncoder(w).Encode(&data)
			}
		})
}
