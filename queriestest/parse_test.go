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
)

const (
	queryParam    = "query"
	matchersParam = "match[]"
)

var okResponse = []byte(`ok`)

var hubKey = "HUB"
var clusterKey = "CLUSTER"
var projectKey = "PROJECT"

func prometheusAPIError(w http.ResponseWriter, errorMessage string, code int) { //nolint:unparam
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

/* assisted by Claude */
func testClusterMatch(t *testing.T, proxyAcmHub string, query string, expectedResources [][][]string, expectedPermissions []string) {
	sliceOfResourceNames, permissions := queries.ParseAuthorizations(hubKey, clusterKey, projectKey, proxyAcmHub, query)

	// Check that we got the expected number of matchers
	if len(sliceOfResourceNames) != len(expectedResources) {
		fmt.Println("Actual:", sliceOfResourceNames)
		fmt.Println("Expected:", expectedResources)
		t.Fatalf("Query %s: Expected %d matchers, got %d", query, len(expectedResources), len(sliceOfResourceNames))
	}

	// Check each matcher's permutations
	for i, expectedMatcher := range expectedResources {
		if len(sliceOfResourceNames[i]) != len(expectedMatcher) {
			fmt.Println("Actual:", sliceOfResourceNames[i])
			fmt.Println("Expected:", expectedMatcher)
			t.Fatalf("Query %s: Matcher %d: Expected %d permutations, got %d", query, i, len(expectedMatcher), len(sliceOfResourceNames[i]))
		}
		
		// Check each permutation
		for j, expectedPermutation := range expectedMatcher {
			if len(sliceOfResourceNames[i][j]) != len(expectedPermutation) {
				fmt.Println("Actual:", sliceOfResourceNames[i][j])
				fmt.Println("Expected:", expectedPermutation)
				t.Fatalf("Query %s: Matcher %d, permutation %d: Expected %d resources, got %d", query, i, j, len(expectedPermutation), len(sliceOfResourceNames[i][j]))
			}
			
			for k, expectedResource := range expectedPermutation {
				if sliceOfResourceNames[i][j][k] != expectedResource {
					fmt.Println("Actual:", sliceOfResourceNames[i][j][k])
					fmt.Println("Expected:", expectedResource)
					t.Fatalf("Query %s: Matcher %d, permutation %d, index %d: Expected %s, got %s", query, i, j, k, expectedResource, sliceOfResourceNames[i][j][k])
				}
			}
		}
	}

	// Check permissions (order may vary due to map iteration)
	if len(permissions) != len(expectedPermissions) {
		fmt.Println("Actual:", permissions)
		fmt.Println("Expected:", expectedPermissions)
		t.Fatalf("Query %s: Expected %d permissions, got %d", query, len(expectedPermissions), len(permissions))
	}

	// Convert to maps for easier comparison
	expectedPermsMap := make(map[string]bool)
	for _, perm := range expectedPermissions {
		expectedPermsMap[perm] = true
	}

	actualPermsMap := make(map[string]bool)
	for _, perm := range permissions {
		actualPermsMap[perm] = true
	}

	for expectedPerm := range expectedPermsMap {
		if !actualPermsMap[expectedPerm] {
			t.Fatalf("Query %s: Expected permission %s not found in actual permissions %v", query, expectedPerm, permissions)
		}
	}

	for actualPerm := range actualPermsMap {
		if !expectedPermsMap[actualPerm] {
			t.Fatalf("Query %s: Unexpected permission %s found in actual permissions", query, actualPerm)
		}
	}
}

/* Assisted by Claude */
func TestClusterMatches(t *testing.T) {
	proxyAcmHub := "test-hub-1"

	// Test querying metrics without any filters
	testClusterMatch(t, proxyAcmHub, `cluster:cpu_cores:sum`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
		},
	)

	// Test querying metrics with empty filter
	testClusterMatch(t, proxyAcmHub, `cluster:cpu_cores:sum{}`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
		},
	)

	// Test querying metrics with empty cluster filter
	testClusterMatch(t, proxyAcmHub, `cluster:cpu_cores:sum{cluster=""}`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
		},
	)

	// Test querying metrics with specific cluster filter
	testClusterMatch(t, proxyAcmHub, `cluster:cpu_cores:sum{cluster="nerc-ocp-test"}`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test")},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
		},
	)

	// Test querying metrics with regex cluster filter
	testClusterMatch(t, proxyAcmHub, `cluster:cpu_cores:sum{cluster=~"nerc-ocp-test|nerc-ocp-prod"}`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"), fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod")},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod"),
		},
	)

	// Test more complex query querying metrics with regex cluster filter
	testClusterMatch(t, proxyAcmHub, `rate(cluster:cpu_cores:sum{cluster=~"nerc-ocp-test|nerc-ocp-prod"}[5m]) + rate(cluster:cpu_cores:sum{cluster="local-cluster"}[5m])`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"), fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod")},
			},
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster")},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod"),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster"),
		},
	)
}

/* Assisted by Claude */
func TestNamespaceMatches(t *testing.T) {
	proxyAcmHub := "test-hub-2"

	// Test querying metrics with cluster and namespace filters
	testClusterMatch(t, proxyAcmHub, `namespace:container_memory_usage_bytes:sum{cluster="nerc-ocp-test",namespace="test"}`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test")},
				{fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "test")},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "test"),
		},
	)

	// Test querying metrics with namespace filter but no cluster filter
	testClusterMatch(t, proxyAcmHub, `namespace:container_memory_usage_bytes:sum{namespace="test"}`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
		},
	)

	// Test querying metrics with regex namespace filter
	testClusterMatch(t, proxyAcmHub, `namespace:container_memory_usage_bytes:sum{cluster="nerc-ocp-test",namespace=~"namespace-a|namespace-b"}`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test")},
				{fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "namespace-a"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "namespace-b")},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "namespace-a"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "namespace-b"),
		},
	)

	// Test more complex query querying metrics with regex namespace filter
	testClusterMatch(t, proxyAcmHub, `rate(namespace:container_memory_usage_bytes:sum{namespace=~"namespace-a|namespace-b"}[1m]) + rate(namespace:container_memory_usage_bytes:sum{cluster="local-cluster",namespace="namespace-b"}[1m])`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
			},
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster")},
				{fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "namespace-b")},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "namespace-b"),
		},
	)
}

/* Assisted by Claude */
// Tests the use case of GPU metrics with the exported_namespace filter.
func TestGpuExportedNamespaceMatches(t *testing.T) {
	proxyAcmHub := "test-hub-3"

	// Test querying metrics with cluster and exported_namespace filters
	testClusterMatch(t, proxyAcmHub, `sum(gpu_operator_gpu_nodes_total{cluster="nerc-ocp-test",exported_namespace="test"})`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test")},
				{fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "test")},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "test"),
		},
	)

	// Test querying metrics with exported_namespace filter only
	testClusterMatch(t, proxyAcmHub, `sum(gpu_operator_gpu_nodes_total{exported_namespace="test"})`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
		},
	)

	// Test more complex query with multiple exported_namespace filters
	testClusterMatch(t, proxyAcmHub, `sum(gpu_operator_gpu_nodes_total{cluster="nerc-ocp-test",exported_namespace="test"}) + sum(gpu_operator_gpu_nodes_total{cluster="local-cluster",exported_namespace=~"prod|exporter"})`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test")},
				{fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "test")},
			},
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster")},
				{fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "prod"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "exporter")},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "test"),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "prod"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "exporter"),
		},
	)

	// Test complex query with mixed namespace and exported_namespace filters
	testClusterMatch(t, proxyAcmHub, `sum(gpu_operator_gpu_nodes_total{cluster=~"nerc-ocp-test|nerc-ocp-prod",namespace="frontend",exported_namespace="monitoring"}) + sum(container_memory_usage_bytes{cluster="local-cluster",namespace=~"backend|api",exported_namespace="logging"})`,
		[][][]string{
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"), fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod")},
				{fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "monitoring"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "frontend"), fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod")},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod", projectKey, "monitoring"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod", projectKey, "frontend")},
				{fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "monitoring"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "frontend"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod", projectKey, "monitoring"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod", projectKey, "frontend")},
			},
			{
				{hubKey},
				{fmt.Sprintf("%s-%s", hubKey, proxyAcmHub)},
				{fmt.Sprintf("%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster")},
				{fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "logging"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "backend"), fmt.Sprintf("%s-%s-%s-%s-%s-%s", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "api")},
			},
		},
		[]string{
			fmt.Sprintf("%s#GET", hubKey),
			fmt.Sprintf("%s-%s#GET", hubKey, proxyAcmHub),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test"),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "frontend"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-test", projectKey, "monitoring"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod", projectKey, "frontend"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "nerc-ocp-prod", projectKey, "monitoring"),
			fmt.Sprintf("%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "backend"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "api"),
			fmt.Sprintf("%s-%s-%s-%s-%s-%s#GET", hubKey, proxyAcmHub, clusterKey, "local-cluster", projectKey, "logging"),
		},
	)
}
