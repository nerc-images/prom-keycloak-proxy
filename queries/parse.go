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

func AppendMatcher(queryValues url.Values, queryValuesForAuth url.Values, key string, defaultValue string) error {
	value := defaultValue
	matchers := queryValues[QueryParam]
	for _, matcher := range matchers {
		matcherSelector, _ := parser.ParseMetricSelector(matcher)

		for _, matcherSelector := range matcherSelector {
			if matcherSelector.Name == key {
				value = matcherSelector.Value
			}
		}
	}
	matcher := &labels.Matcher{
		Name:  key,
		Type:  labels.MatchRegexp,
		Value: LabelValuesToRegexpString([]string{value}),
	}
	err := InjectMatcher(queryValuesForAuth, matcher)
	return err
}

func ParseAuthorizations(queryValues url.Values) url.Values {
	queryValuesForAuth := make(url.Values)

	AppendMatcher(queryValues, queryValuesForAuth, "cluster", "all clusters")
	AppendMatcher(queryValues, queryValuesForAuth, "namespace", "all namespaces")

	return queryValuesForAuth
}

func QueryPrometheus(prometheusTlsCertPath string, prometheusTlsKeyPath string,
	prometheusCaCertPath string, prometheusUrl string) (interface{}, error) {

	prometheusCaCert, err := os.ReadFile(prometheusCaCertPath)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(prometheusCaCert)
	cert, err := tls.LoadX509KeyPair(prometheusTlsCertPath, prometheusTlsKeyPath)
	if err != nil {
		log.Fatal(err)
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
