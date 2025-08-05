package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockViper implements ViperInterface, which allows us to
// provide a fake viper instance to our code for testing.
type mockViper struct {
	stringValues      map[string]string
	boolValues        map[string]bool
	stringSliceValues map[string][]string
}

func newMockViper() *mockViper {
	return &mockViper{
		stringValues:      make(map[string]string),
		boolValues:        make(map[string]bool),
		stringSliceValues: make(map[string][]string),
	}
}

func (m *mockViper) GetString(key string) string {
	return m.stringValues[key]
}

func (m *mockViper) GetBool(key string) bool {
	return m.boolValues[key]
}

func (m *mockViper) GetStringSlice(key string) []string {
	return m.stringSliceValues[key]
}

func (m *mockViper) setString(key, value string) *mockViper {
	m.stringValues[key] = value
	return m
}

func (m *mockViper) setBool(key string, value bool) *mockViper {
	m.boolValues[key] = value
	return m
}

func (m *mockViper) setStringSlice(key string, value []string) *mockViper {
	m.stringSliceValues[key] = value
	return m
}

// validMockViper returns a valid viper configuration (that is, one
// that passes all of our configured validations).
func validMockViper() *mockViper {
	return newMockViper().
		setString("proxy-acm-hub", "test-hub").
		setString("proxy-auth-base-url", "https://auth.example.com").
		setString("proxy-auth-client-id", "test-client").
		setString("proxy-auth-client-secret", "test-secret").
		setString("proxy-auth-realm", "test-realm").
		setBool("proxy-auth-tls-verify", true).
		setString("proxy-cluster-key", "clusterkey123").
		setStringSlice("proxy-cors-allowed-origins", []string{"*"}).
		setString("proxy-hub-key", "hubkey123").
		setString("proxy-project-key", "projectkey123").
		setString("proxy-prometheus-base-url", "https://prometheus.example.com").
		setString("proxy-prometheus-ca-crt", "/path/to/ca.crt").
		setString("proxy-prometheus-tls-crt", "/path/to/tls.crt").
		setString("proxy-prometheus-tls-key", "/path/to/tls.key")
}

// NewProxyConfig returns a ProxyConfig configuration. It is valid
// by default, but can be modified by passing in ProxyConfigOptions.
// We use the tempDir value to create valid paths that can be validated
// using the `file` validator.
func NewProxyConfig(tempDir string, opts ...ProxyConfigOption) *ProxyConfig {
	cfg := &ProxyConfig{
		AcmHub:             "test-hub",
		AuthBaseUrl:        "https://auth.example.com",
		AuthClientId:       "test-client",
		AuthClientSecret:   "test-secret",
		AuthRealm:          "test-realm",
		AuthTlsVerify:      true,
		ClusterKey:         "clusterkey123",
		CorsAllowedOrigins: []string{"*"},
		HubKey:             "hubkey123",
		ProjectKey:         "projectkey123",
		PrometheusBaseUrl:  "https://prometheus.example.com",
		PrometheusCaCrt:    filepath.Join(tempDir, "ca.crt"),
		PrometheusTlsCert:  filepath.Join(tempDir, "tls.crt"),
		PrometheusTlsKey:   filepath.Join(tempDir, "tls.key"),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

// ProxyConfigOption defines a function type that is used to set
// individual values in the ProxyConfig struct. This allows us to
// create a test configuration by doing something like:
//
//	NewProxyConfig(tempDir, WithAcmHub(""))
//
// That gets us a configuration that is missing the AcmHub setting.
type ProxyConfigOption func(*ProxyConfig)

func WithAcmHub(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.AcmHub = value }
}

func WithAuthBaseUrl(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.AuthBaseUrl = value }
}

func WithAuthClientId(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.AuthClientId = value }
}

func WithAuthClientSecret(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.AuthClientSecret = value }
}

func WithAuthRealm(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.AuthRealm = value }
}

func WithAuthTlsVerify(value bool) ProxyConfigOption {
	return func(c *ProxyConfig) { c.AuthTlsVerify = value }
}

func WithClusterKey(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.ClusterKey = value }
}

func WithCorsAllowedOrigins(value []string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.CorsAllowedOrigins = value }
}

func WithHubKey(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.HubKey = value }
}

func WithProjectKey(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.ProjectKey = value }
}

func WithPrometheusBaseUrl(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.PrometheusBaseUrl = value }
}

func WithPrometheusCaCrt(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.PrometheusCaCrt = value }
}

func WithPrometheusTlsCert(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.PrometheusTlsCert = value }
}

func WithPrometheusTlsKey(value string) ProxyConfigOption {
	return func(c *ProxyConfig) { c.PrometheusTlsKey = value }
}

// createTestFile creates file under tempDir and populates it with
// the value of the `content` parameter.
func createTestFile(tempDir, path string, content []byte, mode os.FileMode) (string, error) {
	finalPath := filepath.Join(tempDir, path)
	err := os.WriteFile(finalPath, content, mode)
	return finalPath, err
}

// TestProxyConfig_Validate exercises most of our validations.
func TestProxyConfig_Validate(t *testing.T) {
	// Create temporary directory and files for file validation tests
	tempDir := t.TempDir()

	_, err := createTestFile(tempDir, "ca.crt", []byte("test ca cert"), 0644)
	assert.NoError(t, err)
	_, err = createTestFile(tempDir, "tls.crt", []byte("test tls cert"), 0644)
	assert.NoError(t, err)
	_, err = createTestFile(tempDir, "tls.key", []byte("test tls key"), 0600)
	assert.NoError(t, err)

	tests := []struct {
		name    string
		config  *ProxyConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config",
			config:  NewProxyConfig(tempDir),
			wantErr: false,
		},
		{
			name:    "missing acm hub",
			config:  NewProxyConfig(tempDir, WithAcmHub("")),
			wantErr: true,
			errMsg:  "AcmHub",
		},
		{
			name:    "invalid acm hub with special characters",
			config:  NewProxyConfig(tempDir, WithAcmHub("test@hub")),
			wantErr: true,
			errMsg:  "alphanumhyphen",
		},
		{
			name:    "acm hub not lowercase",
			config:  NewProxyConfig(tempDir, WithAcmHub("Test-Hub")),
			wantErr: true,
			errMsg:  "lowercase",
		},
		{
			name:    "invalid auth base url",
			config:  NewProxyConfig(tempDir, WithAuthBaseUrl("not-a-url")),
			wantErr: true,
			errMsg:  "url",
		},
		{
			name:    "invalid cluster key with special characters",
			config:  NewProxyConfig(tempDir, WithClusterKey("cluster-key")),
			wantErr: true,
			errMsg:  "alphanum",
		},
		{
			name:    "invalid cors origin",
			config:  NewProxyConfig(tempDir, WithCorsAllowedOrigins([]string{"not-a-valid-url-or-star"})),
			wantErr: true,
		},
		{
			name:    "valid cors origins with urls and wildcard",
			config:  NewProxyConfig(tempDir, WithCorsAllowedOrigins([]string{"https://example.com", "*", "http://localhost:3000"})),
			wantErr: false,
		},
		{
			name:    "prometheus url without https",
			config:  NewProxyConfig(tempDir, WithPrometheusBaseUrl("ftp://prometheus.example.com")),
			wantErr: true,
			errMsg:  "startswith",
		},
		{
			name:    "missing ca certificate file",
			config:  NewProxyConfig(tempDir, WithPrometheusCaCrt("/nonexistent/ca.crt")),
			wantErr: true,
			errMsg:  "file",
		},
		{
			name:    "missing tls certificate file",
			config:  NewProxyConfig(tempDir, WithPrometheusTlsCert("/nonexistent/tls.crt")),
			wantErr: true,
			errMsg:  "file",
		},
		{
			name:    "missing tls key file",
			config:  NewProxyConfig(tempDir, WithPrometheusTlsKey("/nonexistent/tls.key")),
			wantErr: true,
			errMsg:  "file",
		},
		{
			name:    "directory instead of file for ca cert",
			config:  NewProxyConfig(tempDir, WithPrometheusCaCrt(tempDir)),
			wantErr: true,
			errMsg:  "file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test that building a ProxyConfig from viper
// values works as expected.
func TestBuildFromViper(t *testing.T) {
	tests := []struct {
		name         string
		viper        ViperInterface
		expectedFunc func(*testing.T, *ProxyConfig)
	}{
		{
			name:  "build valid config from viper",
			viper: validMockViper(),
			expectedFunc: func(t *testing.T, cfg *ProxyConfig) {
				assert.Equal(t, "test-hub", cfg.AcmHub)
				assert.Equal(t, "https://auth.example.com", cfg.AuthBaseUrl)
				assert.Equal(t, "test-client", cfg.AuthClientId)
				assert.Equal(t, "test-secret", cfg.AuthClientSecret)
				assert.Equal(t, "test-realm", cfg.AuthRealm)
				assert.True(t, cfg.AuthTlsVerify)
				assert.Equal(t, "clusterkey123", cfg.ClusterKey)
				assert.Equal(t, []string{"*"}, cfg.CorsAllowedOrigins)
				assert.Equal(t, "hubkey123", cfg.HubKey)
				assert.Equal(t, "projectkey123", cfg.ProjectKey)
				assert.Equal(t, "https://prometheus.example.com", cfg.PrometheusBaseUrl)
				assert.Equal(t, "/path/to/ca.crt", cfg.PrometheusCaCrt)
				assert.Equal(t, "/path/to/tls.crt", cfg.PrometheusTlsCert)
				assert.Equal(t, "/path/to/tls.key", cfg.PrometheusTlsKey)
			},
		},
		{
			name:  "build config with empty values",
			viper: newMockViper(),
			expectedFunc: func(t *testing.T, cfg *ProxyConfig) {
				assert.Empty(t, cfg.AcmHub)
				assert.Empty(t, cfg.AuthBaseUrl)
				assert.Empty(t, cfg.AuthClientId)
				assert.False(t, cfg.AuthTlsVerify)
				assert.Nil(t, cfg.CorsAllowedOrigins)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BuildFromViper(tt.viper)
			tt.expectedFunc(t, cfg)
		})
	}
}

// Test that a ProxyConfig built from a valid
// viper configuration is also valid.
func TestProxyConfig_ValidateIntegration(t *testing.T) {
	tempDir := t.TempDir()

	caCrtFile, err := createTestFile(tempDir, "ca.crt", []byte("test ca cert"), 0644)
	assert.NoError(t, err)
	tlsCrtFile, err := createTestFile(tempDir, "tls.crt", []byte("test tls cert"), 0644)
	assert.NoError(t, err)
	tlsKeyFile, err := createTestFile(tempDir, "tls.key", []byte("test tls key"), 0600)
	assert.NoError(t, err)

	viper := validMockViper().
		setString("proxy-prometheus-ca-crt", caCrtFile).
		setString("proxy-prometheus-tls-crt", tlsCrtFile).
		setString("proxy-prometheus-tls-key", tlsKeyFile)
	cfg := BuildFromViper(viper)

	err = cfg.Validate()
	assert.NoError(t, err, "Valid configuration from viper should pass validation")
}
