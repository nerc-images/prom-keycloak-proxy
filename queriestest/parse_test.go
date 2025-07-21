// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package queries

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/queries"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"golang.org/x/exp/slices"
)

const (
	queryParam    = "query"
	matchersParam = "match[]"
)

var okResponse = []byte(`ok`)

var hubKey = "HUB"
var clusterKey = "CLUSTER"
var projectKey = "PROJECT"

func prometheusAPIError(w http.ResponseWriter, errorMessage string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)

	res := map[string]string{"status": "error", "errorType": "prom-label-proxy", "error": errorMessage}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		log.Printf("error: Failed to encode json: %v", err)
	}
}
func checkParameterAbsent(param string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		kvs, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			prometheusAPIError(w, fmt.Sprintf("unexpected error: %v", err), http.StatusInternalServerError)
			return
		}
		if len(kvs[param]) != 0 {
			prometheusAPIError(w, fmt.Sprintf("unexpected parameter %q", param), http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func checkFormParameterAbsent(param string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			prometheusAPIError(w, fmt.Sprintf("unexpected error: %v", err), http.StatusInternalServerError)
			return
		}
		kvs := req.Form
		if len(kvs[param]) != 0 {
			prometheusAPIError(w, fmt.Sprintf("unexpected Form parameter %q", param), http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// checkQueryHandler verifies that the request form contains the given parameter key/values.
func checkQueryHandler(body, key string, values ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		kvs, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			prometheusAPIError(w, fmt.Sprintf("unexpected error: %v", err), http.StatusInternalServerError)
			return
		}

		// Verify that the client provides the parameter only once.
		if len(kvs[key]) != len(values) {
			prometheusAPIError(w, fmt.Sprintf("expected %d values of parameter %q, got %d", len(values), key, len(kvs[key])), http.StatusInternalServerError)
			return
		}

		sort.Strings(values)
		sort.Strings(kvs[key])
		for i := range values {
			if kvs[key][i] != values[i] {
				prometheusAPIError(w, fmt.Sprintf("expected parameter %q with value %q, got %q", key, values[i], kvs[key][i]), http.StatusInternalServerError)
				return
			}
		}

		buf, err := io.ReadAll(req.Body)
		if err != nil {
			prometheusAPIError(w, "failed to read body", http.StatusInternalServerError)
			return
		}

		if string(buf) != body {
			prometheusAPIError(w, fmt.Sprintf("expected body %q, got %q", body, string(buf)), http.StatusInternalServerError)
			return
		}

		w.Write(okResponse)
		<-time.After(100)
	})
}

// checkFormHandler verifies that the request Form contains the given parameter key/values.
func checkFormHandler(key string, values ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			prometheusAPIError(w, fmt.Sprintf("unexpected error: %v", err), http.StatusInternalServerError)
			return
		}
		kvs := req.PostForm
		// Verify that the client provides the parameter only once.
		if len(kvs[key]) != len(values) {
			prometheusAPIError(w, fmt.Sprintf("expected %d values of parameter %q, got %d", len(values), key, len(kvs[key])), http.StatusInternalServerError)
			return
		}
		sort.Strings(values)
		sort.Strings(kvs[key])
		for i := range values {
			if kvs[key][i] != values[i] {
				prometheusAPIError(w, fmt.Sprintf("expected parameter %q with value %q, got %q", key, values[i], kvs[key][i]), http.StatusInternalServerError)
				return
			}
		}
		w.Write(okResponse)
		<-time.After(100)
	})
}

// mockUpstream simulates an upstream HTTP server. It runs on localhost.
type mockUpstream struct {
	h   http.Handler
	srv *httptest.Server
	url *url.URL
}

func newMockUpstream(h http.Handler) *mockUpstream {
	m := mockUpstream{h: h}

	m.srv = httptest.NewServer(&m)

	u, err := url.Parse(m.srv.URL)
	if err != nil {
		panic(err)
	}
	m.url = u

	return &m
}

func (m *mockUpstream) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	m.h.ServeHTTP(w, req)
}

func (m *mockUpstream) Close() {
	m.srv.Close()
}

func labelValuesToRegexpString(labelValues []string) string {
	lvs := make([]string, len(labelValues))
	for i := range labelValues {
		lvs[i] = regexp.QuoteMeta(labelValues[i])
	}

	return strings.Join(lvs, "|")
}

func matchersToString(ms ...*labels.Matcher) string {
	var el []string
	for _, m := range ms {
		el = append(el, m.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}

func injectMatcher(q url.Values, matcher *labels.Matcher) error {
	matchers := q[matchersParam]
	if len(matchers) == 0 {
		q.Set(matchersParam, matchersToString(matcher))
		return nil
	}

	// Inject label into existing matchers.
	for i, m := range matchers {
		ms, err := parser.ParseMetricSelector(m)
		if err != nil {
			return err
		}

		matchers[i] = matchersToString(append(ms, matcher)...)
	}
	q[matchersParam] = matchers

	return nil
}

func testClusterMatch(t *testing.T, proxyAcmHub string, query string, expectedKeys []string, expectedValues []string) {
	urlString := fmt.Sprintf("%s%s?query=%s", "http://prometheus:9090", "/api/v1/query", url.QueryEscape(query))

	u, err := url.Parse(urlString)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	q := u.Query()

	_, keys, values := queries.ParseAuthorizations(hubKey, clusterKey, projectKey, proxyAcmHub, q)

	if len(keys) != len(expectedKeys) {
		t.Fatalf("%s: Expected %d keys for authorization, but found %d", query, len(expectedKeys), len(keys))
	}
	if len(values) != len(expectedValues) {
		t.Fatalf("%s: Expected %d values for authorization, but found %d", query, len(expectedValues), len(values))
	}
	for index, key := range keys {
		value := values[index]
		if slices.Index(expectedKeys, key) == -1 {
			t.Fatalf("%s: The query key %s was not found in the expected keys", query, key)
		}
		expectedKey := expectedKeys[slices.Index(expectedKeys, key)]
		if slices.Index(expectedValues, value) == -1 {
			t.Fatalf("%s: The query value %s was not found in the expected values", query, value)
		}
		expectedValue := expectedValues[slices.Index(expectedKeys, key)]
		if key != expectedKey {
			t.Fatalf("%s: Expected %s key for authorization, but found %s", query, expectedKey, key)
		}
		if value != expectedValue {
			t.Fatalf("%s: Expected %s value for authorization, but found %s", query, expectedValue, value)
		}
	}
}

// Tests cluster filter metrics.
func TestClusterMatches(t *testing.T) {
	proxyAcmHub := "MyHub"

	// Test querying metrics without any filters
	// Expect the following authorization permissions:
	testClusterMatch(t, proxyAcmHub, `cluster:cpu_cores:sum`,
		[]string{
			// - A user with the "HUB" permission can view all metrics in all tenants.
			hubKey,
			// - A user with the HUB-$PROXY_ACM_HUB permission can view all metrics for all clusters in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
		[]string{"GET", "GET"})

	// Test querying metrics with a filter on a specific nerc-ocp-prod cluster in the $PROXY_ACM_HUB tenant.
	// Expect the following authorization permissions:
	testClusterMatch(t, proxyAcmHub, `cluster:cpu_cores:sum{cluster="nerc-ocp-prod"}`,
		[]string{
			// - A user with the "HUB" permission can view all metrics in all tenants.
			hubKey,
			// - A user with the HUB-$PROXY_ACM_HUB permission can view all metrics for all clusters in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s", hubKey, proxyAcmHub),
			// - A user with the HUB-$PROXY_ACM_HUB-CLUSTER-nerc-ocp-prod permission can view all metrics for the nerc-ocp-prod cluster in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod")},
		[]string{"GET", "GET", "GET"})
}

// Tests various namespace filters with and without a cluster.
func TestNamespaceMatches(t *testing.T) {
	proxyAcmHub := "MyHub"

	// Test querying metrics with a filter on a specific test project in the nerc-ocp-prod cluster in the $PROXY_ACM_HUB tenant.
	// Expect the following authorization permissions:
	testClusterMatch(t, proxyAcmHub, `namespace:container_memory_usage_bytes:sum{cluster="nerc-ocp-test",namespace="test"}`,
		[]string{
			// - A user with the "HUB" permission can view all metrics in all tenants.
			hubKey,
			// - A user with the HUB-$PROXY_ACM_HUB permission can view all metrics for all clusters in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s", hubKey, proxyAcmHub),
			// - A user with the HUB-$PROXY_ACM_HUB-CLUSTER-nerc-ocp-test permission can view all metrics for the nerc-ocp-test cluster in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
			// - A user with the HUB-$PROXY_ACM_HUB-CLUSTER-nerc-ocp-test-PROJECT-test permission can view all metrics for the test project in the nerc-ocp-test cluster in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "test")},
		[]string{"GET", "GET", "GET", "GET"})

	// Test querying metrics with a filter on a specific test project witout a filter on a cluster in the $PROXY_ACM_HUB tenant.
	// Because no cluster was specified as a filter, this query requires permissions for the $PROXY_ACM_HUB tenant, or all tenants.
	// Expect the following authorization permissions:
	testClusterMatch(t, proxyAcmHub, `namespace:container_memory_usage_bytes:sum{namespace="test"}`,
		[]string{
			// - A user with the "HUB" permission can view all metrics in all tenants.
			"HUB",
			// - A user with the HUB-$PROXY_ACM_HUB permission can view all metrics for all clusters in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
		[]string{"GET", "GET"})
}

// Tests the use case of GPU metrics with the exported_namespace filter.
func TestGpuExportedNamespaceMatches(t *testing.T) {
	proxyAcmHub := "MyHub"

	// Test querying metrics with a filter on a specific nerc-ocp-prod cluster in the $PROXY_ACM_HUB tenant.
	// Expect the following authorization permissions:
	testClusterMatch(t, proxyAcmHub, `sum(gpu_operator_gpu_nodes_total{cluster="nerc-ocp-test"})`,
		[]string{
			// - A user with the "HUB" permission can view all metrics in all tenants.
			hubKey,
			// - A user with the HUB-$PROXY_ACM_HUB permission can view all metrics for all clusters in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s", hubKey, proxyAcmHub),
			// - A user with the HUB-$PROXY_ACM_HUB-CLUSTER-nerc-ocp-prod permission can view all metrics for the nerc-ocp-prod cluster in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test")},
		[]string{"GET", "GET", "GET"})

	// Test querying metrics with a filter on a specific test project in the nerc-ocp-prod cluster in the $PROXY_ACM_HUB tenant.
	// Expect the following authorization permissions:
	testClusterMatch(t, proxyAcmHub, `sum(gpu_operator_gpu_nodes_total{cluster="nerc-ocp-test",exported_namespace="test"})`,
		[]string{
			// - A user with the "HUB" permission can view all metrics in all tenants.
			hubKey,
			// - A user with the HUB-$PROXY_ACM_HUB permission can view all metrics for all clusters in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s", hubKey, proxyAcmHub),
			// - A user with the HUB-$PROXY_ACM_HUB-CLUSTER-nerc-ocp-test permission can view all metrics for the nerc-ocp-test cluster in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
			// - A user with the HUB-$PROXY_ACM_HUB-CLUSTER-nerc-ocp-test-PROJECT-test permission can view all metrics for the test project in the nerc-ocp-test cluster in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "test")},
		[]string{"GET", "GET", "GET", "GET"})

	// Test querying metrics with a filter on a specific test project witout a filter on a cluster in the $PROXY_ACM_HUB tenant.
	// Because no cluster was specified as a filter, this query requires permissions for the $PROXY_ACM_HUB tenant, or all tenants.
	// Expect the following authorization permissions:
	testClusterMatch(t, proxyAcmHub, `sum(gpu_operator_gpu_nodes_total{exported_namespace="test"})`,
		[]string{
			// - A user with the "HUB" permission can view all metrics in all tenants.
			"HUB",
			// - A user with the HUB-$PROXY_ACM_HUB permission can view all metrics for all clusters in the $PROXY_ACM_HUB tenant.
			fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
		[]string{"GET", "GET"})
}
