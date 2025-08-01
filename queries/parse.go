package queries

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

const (
	QueryParam    = "query"
	MatchersParam = "match[]"
)

func ParseQuery(query string) (ms []*labels.Matcher, err error) {
	m, err := parser.ParseMetricSelector(query)
	return m, err
}

func LabelValuesToRegexpString(labelValues []string) string {
	lvs := make([]string, len(labelValues))
	for i := range labelValues {
		lvs[i] = regexp.QuoteMeta(labelValues[i])
	}

	return strings.Join(lvs, "|")
}
func MatchersToString(ms ...*labels.Matcher) string {
	var el []string
	for _, m := range ms {
		el = append(el, m.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}

func InjectMatcher(q url.Values, matcher *labels.Matcher) error {
	matchers := q[QueryParam]
	if len(matchers) == 0 {
		q.Set(QueryParam, MatchersToString(matcher))
		return nil
	}

	// Inject label into existing matchers.
	for i, m := range matchers {
		ms, err := parser.ParseMetricSelector(m)
		if err != nil {
			return err
		}

		matchers[i] = MatchersToString(append(ms, matcher)...)
	}
	q[QueryParam] = matchers

	return nil
}

func AppendMatcher(queryValues url.Values, queryValuesForAuth url.Values, key string, authKey string, defaultValue string) (string, error) {
	value := defaultValue
	expr, exprErr := parser.ParseExpr(queryValues[QueryParam][0])
	matchers := parser.ExtractSelectors(expr)
	if exprErr != nil {
		log.Panic(exprErr)
	}
	for _, matcherSelector := range matchers {
		for _, matcherSelector := range matcherSelector {
			if matcherSelector.Name == key {
				value = matcherSelector.Value
			}
		}
	}

	if value != "" {
		matcher := &labels.Matcher{
			Name:  authKey,
			Type:  labels.MatchRegexp,
			Value: LabelValuesToRegexpString([]string{value}),
		}
		err := InjectMatcher(queryValuesForAuth, matcher)
		return value, err
	}
	return value, nil
}

func ParseAuthorizations(hubKey string, clusterKey string, projectKey string, hub string, queryValues url.Values) (url.Values, []string, []string) {
	queryValuesForAuth := make(url.Values)

	var authResourceNames []string
	var authScopeNames []string

	authResourceNames = append(authResourceNames, hubKey)
	authScopeNames = append(authScopeNames, "GET")

	authResourceNames = append(authResourceNames, fmt.Sprintf("%s-%s", hubKey, hub))
	authScopeNames = append(authScopeNames, "GET")

	cluster, _ := AppendMatcher(queryValues, queryValuesForAuth, "cluster", fmt.Sprintf("%s-%s-%s", hubKey, hub, clusterKey), "")

	if cluster != "" {
		authResourceNames = append(authResourceNames, fmt.Sprintf("%s-%s-%s-%s", hubKey, hub, clusterKey, cluster))
		authScopeNames = append(authScopeNames, "GET")

		exported_namespace, _ := AppendMatcher(queryValues, queryValuesForAuth, "exported_namespace", fmt.Sprintf("%s-%s-%s-%s-%s", hubKey, hub, clusterKey, cluster, projectKey), "")
		namespace, _ := AppendMatcher(queryValues, queryValuesForAuth, "namespace", fmt.Sprintf("%s-%s-%s-%s-%s", hubKey, hub, clusterKey, cluster, projectKey), exported_namespace)

		if namespace != "" {
			if cluster != "" {
				authResourceNames = append(authResourceNames, fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, hub, clusterKey, cluster, projectKey, namespace))
				authScopeNames = append(authScopeNames, "GET")
			}
		}
	}

	return queryValuesForAuth, authResourceNames, authScopeNames
}

func QueryPrometheus(prometheusTlsCertPath string, prometheusTlsKeyPath string,
	prometheusCaCertPath string, prometheusUrl string) (interface{}, error) {
	prometheusCaCert, err := os.ReadFile(prometheusCaCertPath)
	if err != nil {
		log.Panic(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(prometheusCaCert)
	cert, err := tls.LoadX509KeyPair(prometheusTlsCertPath, prometheusTlsKeyPath)
	if err != nil {
		log.Panic(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	response, err := client.Get(prometheusUrl)
	if err == nil {
		defer response.Body.Close()
		var data interface{}
		json.NewDecoder(response.Body).Decode(&data)
		return data, err
	} else {
		return nil, err
	}
}
