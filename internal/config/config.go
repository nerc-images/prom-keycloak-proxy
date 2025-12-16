package config

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

// ProxyConfig holds our configuration values and defines
// our validations for those values.
type ProxyConfig struct {
	AcmHub             string   `validate:"required,alphanumhyphen,lowercase"`
	AuthBaseUrl        string   `validate:"required,url"`
	AuthClientId       string   `validate:"required,alphanumhyphen"`
	AuthClientSecret   string   `validate:"required,ascii"`
	AuthRealm          string   `validate:"required,alphanumhyphen"`
	AuthTlsVerify      bool     `validate:"boolean"`
	ClusterKey         string   `validate:"required,alphanum"`
	CorsAllowedOrigins []string `validate:"dive,url|eq=*"`
	HubKey             string   `validate:"required,alphanum"`
	ProjectKey         string   `validate:"required,alphanum"`
	PrometheusBaseUrl  string   `validate:"required,url,startswith=http:|startswith=https:"`
	PrometheusCaCert   string   `validate:"omitempty,file"`
	PrometheusTlsCert  string   `validate:"omitempty,file"`
	PrometheusTlsKey   string   `validate:"omitempty,file"`
	PrometheusToken    string   `validate:"omitempty,ascii"`
	OpenshiftLocal     bool     `validate:"boolean"`
}

// NewValidator returns a new validator with our custom
// validations already registered.
func NewValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.RegisterValidation("alphanumhyphen", validateAlphanumericWithHyphen) //nolint:errcheck
	return v
}

func validateAlphanumericWithHyphen(fl validator.FieldLevel) bool {
	regex := regexp.MustCompile("^[a-zA-Z0-9-]+$")
	return regex.MatchString(fl.Field().String())
}

// Runs a validator against the values contained in a
// ProxyConfig variable.
func (c *ProxyConfig) Validate() error {
	return NewValidator().Struct(c)
}

// BuildFromViper creates a new ProxyConfig instance from viper configuration
// values (which may come from the command line or the environment).
func BuildFromViper(v ViperInterface) *ProxyConfig {
	return &ProxyConfig{
		AcmHub:             v.GetString("proxy-acm-hub"),
		AuthBaseUrl:        v.GetString("proxy-auth-base-url"),
		AuthClientId:       v.GetString("proxy-auth-client-id"),
		AuthClientSecret:   v.GetString("proxy-auth-client-secret"),
		AuthRealm:          v.GetString("proxy-auth-realm"),
		AuthTlsVerify:      v.GetBool("proxy-auth-tls-verify"),
		CorsAllowedOrigins: v.GetStringSlice("proxy-cors-allowed-origins"),
		ClusterKey:         v.GetString("proxy-cluster-key"),
		HubKey:             v.GetString("proxy-hub-key"),
		ProjectKey:         v.GetString("proxy-project-key"),
		PrometheusBaseUrl:  v.GetString("proxy-prometheus-base-url"),
		PrometheusCaCert:   v.GetString("proxy-prometheus-ca-cert"),
		PrometheusTlsCert:  v.GetString("proxy-prometheus-tls-cert"),
		PrometheusTlsKey:   v.GetString("proxy-prometheus-tls-key"),
		PrometheusToken:    v.GetString("proxy-prometheus-token"),
		OpenshiftLocal:     v.GetBool("openshift-local"),
	}
}
