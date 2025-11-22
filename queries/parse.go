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
	QueryParam       = "query"
	MatchersParam    = "match[]"
	MetricPattern    = "[a-zA-Z_:][a-zA-Z0-9_:]*"
	LabelNamePattern = "[a-zA-Z_][a-zA-Z0-9_]*"
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

func AppendMatcher(queryValues url.Values, queryValuesForAuth url.Values, key string, authKey string, defaultValue string) (string, labels.MatchType, error) {
	value := defaultValue
	matchType := labels.MatchEqual
	expr, exprErr := parser.ParseExpr(queryValues[QueryParam][0])
	matchers := parser.ExtractSelectors(expr)
	if exprErr != nil {
		log.Panic(exprErr)
	}
	for _, matcherSelector := range matchers {
		for _, matcherSelector := range matcherSelector {
			if matcherSelector.Name == key {
				value = matcherSelector.Value
				matchType = matcherSelector.Type
			}
		}
	}

	if value != "" {
		matcher := &labels.Matcher{
			Name:  authKey,
			Type:  matchType,
			Value: LabelValuesToRegexpString([]string{value}),
		}
		err := InjectMatcher(queryValuesForAuth, matcher)
		return value, matchType, err
	}
	return value, matchType, nil
}

// ParseAuthorizations extracts authorization requirements from a PromQL query and generates
// all possible permission name combinations needed to execute the query.
//
// Parameters:
//   - hubKey: The base hub identifier prefix (e.g., "HUB")
//   - clusterKey: The base cluster identifier prefix (e.g., "CLUSTER")
//   - projectKey: The base namespace/projcet identifier prefix (e.g., "PROJECT")
//   - hub: The specific hub name (e.g., "innabox-dev")
//   - promqlQuery: The PromQL query string to analyze
//
// Returns:
//   - [][][]string: A 3D slice where:
//   - First dimension: Each matcher/selector in the query (one for each curly bracket pair {})
//   - Second dimension: A list of resource names that the client must have all permissions for in Keycloak order to submit the query
//   - Third dimension: Individual resource name
//   - []string: List of all unique required permissions with the "GET" keycloak scope appended
//
// Example:
//
//	Query: sum(metric1{cluster=~"c1|c2",namespace=~"n1|n2"}) + sum(metric2{cluster="c3",exported_namespace="n3",namespace="n4"})
//	Returns:
//	[][][]string {
//	  {
//	    {HUB},
//	    {HUB-hub},
//	    {HUB-hub-CLUSTER-c1, HUB-hub-CLUSTER-c2},
//	    {HUB-hub-CLUSTER-c1-PROJECT-n1, HUB-hub-CLUSTER-c1-PROJECT-n2, HUB-hub-CLUSTER-c2},
//	    {HUB-hub-CLUSTER-c1, HUB-hub-CLUSTER-c2-PROJECT-n1, HUB-hub-CLUSTER-c2-PROJECT-n2},
//	    {HUB-hub-CLUSTER-c1-PROJECT-n1, HUB-hub-CLUSTER-c1-PROJECT-n2, HUB-hub-CLUSTER-c2-PROJECT-n1, HUB-hub-CLUSTER-c2-PROJECT-n2},
//	  },
//	  {
//	    {HUB},
//	    {HUB-hub},
//	    {HUB-hub-CLUSTER-c3},
//	    {HUB-hub-CLUSTER-c3-PROJECT-n3, HUB-hub-CLUSTER-c3-PROJECT-n4},
//	  },
//	},
//	[]string {
//	  HUB,
//	  HUB-hub,
//	  HUB-hub-CLUSTER-c1,
//	  HUB-hub-CLUSTER-c1-PROJECT-n1,
//	  HUB-hub-CLUSTER-c1-PROJECT-n2,
//	  HUB-hub-CLUSTER-c2,
//	  HUB-hub-CLUSTER-c2-PROJECT-n1,
//	  HUB-hub-CLUSTER-c2-PROJECT-n2,
//	  HUB-hub-CLUSTER-c3,
//	  HUB-hub-CLUSTER-c3-PROJECT-n3,
//	  HUB-hub-CLUSTER-c3-PROJECT-n4,
//	}
func ParseAuthorizations(hubKey string, clusterKey string, projectKey string, hub string, openshiftLocal bool, promqlQuery string) ([][][]string, []string) {
	expr, exprErr := parser.ParseExpr(promqlQuery)
	if exprErr != nil {
		log.Panic(exprErr)
	}

	matchers := parser.ExtractSelectors(expr)
	if len(matchers) == 0 {
		return [][][]string{
				{
					{hubKey},
					{fmt.Sprintf("%s-%s", hubKey, hub)},
				},
			},
			[]string{
				hubKey + "#GET",
				fmt.Sprintf("%s-%s#GET", hubKey, hub),
			}
	}

	resources := make([][][]string, len(matchers))
	uniqueResources := make(map[string]struct{})
	uniqueResources[hubKey] = struct{}{}
	uniqueResources[fmt.Sprintf("%s-%s", hubKey, hub)] = struct{}{}

	for i, matcher := range matchers {
		resources[i] = append(resources[i], []string{hubKey})
		resources[i] = append(resources[i], []string{fmt.Sprintf("%s-%s", hubKey, hub)})

		var clusterMatcher *labels.Matcher = nil
		var namespaceMatcher *labels.Matcher = nil
		var exportedNamespaceMatcher *labels.Matcher = nil

		for _, matcherSelector := range matcher {
			switch matcherSelector.Name {
			case "cluster":
				clusterMatcher = matcherSelector
			case "namespace":
				namespaceMatcher = matcherSelector
			case "exported_namespace":
				exportedNamespaceMatcher = matcherSelector
			default:
				continue
			}
		}

		if !openshiftLocal && (clusterMatcher == nil || clusterMatcher.Value == "") {
			continue
		}

		var clusterValues []string
		if !openshiftLocal {
			if clusterMatcher.Type == labels.MatchEqual {
				clusterValues = append(clusterValues, clusterMatcher.Value)
			} else {
				clusterValues = strings.Split(clusterMatcher.Value, "|")
				for j, clusterValue := range clusterValues {
					clusterValues[j] = regexp.QuoteMeta(clusterValue)
				}
			}
		}

		var namespaceValues []string
		if exportedNamespaceMatcher != nil {
			if exportedNamespaceMatcher.Type == labels.MatchEqual {
				namespaceValues = append(namespaceValues, exportedNamespaceMatcher.Value)
			} else {
				namespaces := strings.Split(exportedNamespaceMatcher.Value, "|")
				for _, namespace := range namespaces {
					if exportedNamespaceMatcher.Type != labels.MatchNotEqual || exportedNamespaceMatcher.Value != "" {
						namespaceValues = append(namespaceValues, regexp.QuoteMeta(namespace))
					}
				}
			}
		}
		if namespaceMatcher != nil {
			if namespaceMatcher.Type == labels.MatchEqual {
				namespaceValues = append(namespaceValues, namespaceMatcher.Value)
			} else {
				namespaces := strings.Split(namespaceMatcher.Value, "|")
				for _, namespace := range namespaces {
					if namespaceMatcher.Type != labels.MatchNotEqual || namespaceMatcher.Value != "" {
						namespaceValues = append(namespaceValues, regexp.QuoteMeta(namespace))
					}
				}
			}
		}

		if len(namespaceValues) == 0 {
			var clusterResources []string
			for _, clusterValue := range clusterValues {
				clusterResources = append(clusterResources, fmt.Sprintf("%s-%s-%s-%s", hubKey, hub, clusterKey, clusterValue))
				uniqueResources[fmt.Sprintf("%s-%s-%s-%s", hubKey, hub, clusterKey, clusterValue)] = struct{}{}
			}
			if !openshiftLocal {
				resources[i] = append(resources[i], clusterResources)
			}
			continue
		}

		/* BEGIN assisted by Claude */
		// there are math.Pow(2, len(clusters)) combinations of resource names to check
		totalCombinations := 1 << len(clusterValues)

		// a binary integer variable can represent all combinations of 1s and 0s up to a max value (totalCombinations) by incrementing
		// we want to append either the cluster-scoped resource name or the namespace-scoped resource names
		// we can do this by associating the 1s and 0s to cluster-scoped and namespace-scoped resource names
		if !openshiftLocal {
			// Determine resources for Red Hat Advanced Cluster Management Observability clusters
			var combinationBitMap int
			for combinationBitMap = 0; combinationBitMap < totalCombinations; combinationBitMap++ {
				var namespaceResources []string
				for bitOffset, clusterValue := range clusterValues {
					if (combinationBitMap>>bitOffset)&1 == 0 {
						namespaceResources = append(namespaceResources, fmt.Sprintf("%s-%s-%s-%s", hubKey, hub, clusterKey, clusterValue))
						uniqueResources[fmt.Sprintf("%s-%s-%s-%s", hubKey, hub, clusterKey, clusterValue)] = struct{}{}
					} else {
						for _, namespaceValue := range namespaceValues {
							namespaceResources = append(namespaceResources, fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, hub, clusterKey, clusterValue, projectKey, namespaceValue))
							uniqueResources[fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, hub, clusterKey, clusterValue, projectKey, namespaceValue)] = struct{}{}
						}
					}
				}

				resources[i] = append(resources[i], namespaceResources)
			}
		} else {
			// Determine resources for OpenShift Local clusters
			clusterValue := ""
			var combinationBitMap int
			for combinationBitMap = 0; combinationBitMap < totalCombinations; combinationBitMap++ {
				var namespaceResources []string
				for _, namespaceValue := range namespaceValues {
					namespaceResources = append(namespaceResources, fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, hub, clusterKey, clusterValue, projectKey, namespaceValue))
					uniqueResources[fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, hub, clusterKey, clusterValue, projectKey, namespaceValue)] = struct{}{}
				}

				resources[i] = append(resources[i], namespaceResources)
			}
		}
		/* END assisted by Claude */
	}

	permissions := make([]string, len(uniqueResources))
	i := 0
	for resource := range uniqueResources {
		permissions[i] = resource + "#GET"
		i++
	}

	return resources, permissions
}

func QueryPrometheus(prometheusTlsCertPath string, prometheusTlsKeyPath string,
	prometheusCaCertPath string, prometheusToken string, authTlsVerify bool, prometheusUrl string) (interface{}, error) {
	var client *http.Client
	if prometheusTlsCertPath != "" && prometheusTlsKeyPath != "" && prometheusCaCertPath != "" {
		prometheusCaCert, err := os.ReadFile(prometheusCaCertPath)
		if err != nil {
			log.Panic(err)
		}

		var caCertPool *x509.CertPool
		var cert tls.Certificate

		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(prometheusCaCert)
		cert, err = tls.LoadX509KeyPair(prometheusTlsCertPath, prometheusTlsKeyPath)
		if err != nil {
			log.Panic(err)
		}

		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            caCertPool,
					Certificates:       []tls.Certificate{cert},
					InsecureSkipVerify: !authTlsVerify,
				},
			},
		}
	} else {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !authTlsVerify,
				},
			},
		}
	}

	req, err := http.NewRequest(http.MethodGet, prometheusUrl, nil)
	if err != nil {
		log.Panic(err)
	}
	if prometheusToken != "" {
		req.Header.Add("Authorization", "Bearer "+prometheusToken)
	}

	response, err := client.Do(req)
	if err == nil {
		defer response.Body.Close() //nolint:errcheck
		var data interface{}
		json.NewDecoder(response.Body).Decode(&data) //nolint:errcheck
		return data, err
	} else {
		return nil, err
	}
}
