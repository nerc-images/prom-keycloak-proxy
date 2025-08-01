// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/services"
	"github.com/go-playground/validator/v10"
	"github.com/jzelinskie/cobrautil"
	"github.com/jzelinskie/stringz"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var validate *validator.Validate

func main() {
	run()
}
func run() {
	rootCmd := &cobra.Command{
		Use:     "prom-keycloak-proxy",
		Short:   "Proxy that protects Prometheus queries with Keycloak fine-grained resource permissions",
		PreRunE: cobrautil.SyncViperPreRunE("prom-keycloak-proxy"),
		RunE: cobrautil.CommandStack(
			cobrautil.ZeroLogRunE("log", zerolog.InfoLevel),
			cobrautil.OpenTelemetryRunE("otel", zerolog.InfoLevel),
			rootRunE,
		),
	}

	flags := rootCmd.Flags()
	cobrautil.RegisterZeroLogFlags(flags, "log")
	cobrautil.RegisterOpenTelemetryFlags(flags, "otel", "prom-keycloak-proxy")
	cobrautil.RegisterHTTPServerFlags(flags, "metrics", "metrics", ":9091", true)

	cobrautil.RegisterHTTPServerFlags(flags, "proxy", "proxy", ":8080", true)
	flags.StringSlice("proxy-cors-allowed-origins", []string{"*"}, "allowed origins for CORS requests")

	flags.String("proxy-acm-hub", "", "ACM Hub name")
	viper.BindPFlag("proxy-acm-hub", flags.Lookup("proxy-acm-hub"))
	viper.BindEnv("proxy-acm-hub", "PROXY_ACM_HUB")

	flags.String("proxy-auth-client-id", "", "Keycloak auth client ID")
	viper.BindPFlag("proxy-auth-client-id", flags.Lookup("proxy-auth-client-id"))
	viper.BindEnv("proxy-auth-client-id", "PROXY_AUTH_CLIENT_ID")

	flags.String("proxy-auth-client-secret", "", "Keycloak auth client secret")
	viper.BindPFlag("proxy-auth-client-secret", flags.Lookup("proxy-auth-client-secret"))
	viper.BindEnv("proxy-auth-client-secret", "PROXY_AUTH_CLIENT_SECRET")

	flags.String("proxy-auth-realm", "", "Keycloak auth realm")
	viper.BindPFlag("proxy-auth-realm", flags.Lookup("proxy-auth-realm"))
	viper.BindEnv("proxy-auth-realm", "PROXY_AUTH_REALM")

	flags.String("proxy-auth-base-url", "", "Keycloak base URL")
	viper.BindPFlag("proxy-auth-base-url", flags.Lookup("proxy-auth-base-url"))
	viper.BindEnv("proxy-auth-base-url", "PROXY_AUTH_BASE_URL")

	flags.Bool("proxy-auth-tls-verify", true, "connect to keycloak and verify valid TLS")
	viper.BindPFlag("proxy-auth-tls-verify", flags.Lookup("proxy-auth-tls-verify"))
	viper.BindEnv("proxy-auth-tls-verify", "PROXY_AUTH_TLS_VERIFY")

	flags.String("proxy-prometheus-base-url", "", "address of the prometheus to use for checking")
	viper.BindPFlag("proxy-prometheus-base-url", flags.Lookup("proxy-prometheus-base-url"))
	viper.BindEnv("proxy-prometheus-base-url", "PROXY_PROMETHEUS_BASE_URL")

	flags.String("proxy-prometheus-tls-crt", "", "path at which to find a certificate for prometheus TLS")
	viper.BindPFlag("proxy-prometheus-tls-crt", flags.Lookup("proxy-prometheus-tls-crt"))
	viper.BindEnv("proxy-prometheus-tls-crt", "PROXY_PROMETHEUS_TLS_CRT")

	flags.String("proxy-prometheus-tls-key", "", "path at which to find a private key for prometheus TLS")
	viper.BindPFlag("proxy-prometheus-tls-key", flags.Lookup("proxy-prometheus-tls-key"))
	viper.BindEnv("proxy-prometheus-tls-key", "PROXY_PROMETHEUS_TLS_KEY")

	flags.String("proxy-prometheus-ca-crt", "", "path at which to find a ca certificate for prometheus TLS")
	viper.BindPFlag("proxy-prometheus-ca-crt", flags.Lookup("proxy-prometheus-ca-crt"))
	viper.BindEnv("proxy-prometheus-ca-crt", "PROXY_PROMETHEUS_CA_CRT")

	flags.String("proxy-hub-key", "", "The hub key to use for auth resources")
	viper.BindPFlag("proxy-hub-key", flags.Lookup("proxy-hub-key"))
	viper.BindEnv("proxy-hub-key", "PROXY_HUB_KEY")

	flags.String("proxy-cluster-key", "", "The cluster key to use for auth resources")
	viper.BindPFlag("proxy-cluster-key", flags.Lookup("proxy-cluster-key"))
	viper.BindEnv("proxy-cluster-key", "PROXY_CLUSTER_KEY")

	flags.String("proxy-project-key", "", "The project key to use for auth resources")
	viper.BindPFlag("proxy-project-key", flags.Lookup("proxy-project-key"))
	viper.BindEnv("proxy-project-key", "PROXY_PROJECT_KEY")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func ValidateAlphanumericWithHyphen(fl validator.FieldLevel) bool {
	//  Regex to match alphanumeric characters and hyphens
	regex := regexp.MustCompile("^[a-zA-Z0-9-]+$")
	return regex.MatchString(fl.Field().String())
}

func rootRunE(cmd *cobra.Command, args []string) error {
	proxyPrometheusBaseUrl, err := url.Parse(viper.GetString("proxy-prometheus-base-url"))
	if err != nil {
		return fmt.Errorf("failed to build parse upstream URL: %w", err)
	}
	if !stringz.SliceContains([]string{"http", "https"}, proxyPrometheusBaseUrl.Scheme) {
		return errors.New("only 'http' and 'https' schemes are supported for the upstream prometheus URL")
	}

	validate = validator.New(validator.WithRequiredStructEnabled())
	validate.RegisterValidation("alphanumhyphen", ValidateAlphanumericWithHyphen)

	type ProxyVars struct {
		ProxyAcmHub            string `validate:"required,alphanumhyphen,lowercase"`
		ProxyAuthClientId      string `validate:"required,alphanumhyphen"`
		ProxyAuthClientSecret  string `validate:"required,ascii"`
		ProxyAuthRealm         string `validate:"required,alphanumhyphen"`
		ProxyAuthBaseUrl       string `validate:"required,url"`
		ProxyAuthTlsVerify     bool   `validate:"required"`
		ProxyPrometheusBaseUrl string `validate:"required,url"`
		ProxyPrometheusTlsCert string `validate:"required,filepath"`
		ProxyPrometheusTlsKey  string `validate:"required,filepath"`
		ProxyPrometheusCaCrt   string `validate:"required,filepath"`
		ProxyHubKey            string `validate:"required,alphanum"`
		ProxyClusterKey        string `validate:"required,alphanum"`
		ProxyProjectKey        string `validate:"required,alphanum"`
	}

	vars := &ProxyVars{
		ProxyAcmHub:            viper.GetString("proxy-acm-hub"),
		ProxyAuthClientId:      viper.GetString("proxy-auth-client-id"),
		ProxyAuthClientSecret:  viper.GetString("proxy-auth-client-secret"),
		ProxyAuthRealm:         viper.GetString("proxy-auth-realm"),
		ProxyAuthBaseUrl:       viper.GetString("proxy-auth-base-url"),
		ProxyAuthTlsVerify:     viper.GetBool("proxy-auth-tls-verify"),
		ProxyPrometheusBaseUrl: viper.GetString("proxy-prometheus-base-url"),
		ProxyPrometheusTlsCert: viper.GetString("proxy-prometheus-tls-crt"),
		ProxyPrometheusTlsKey:  viper.GetString("proxy-prometheus-tls-key"),
		ProxyPrometheusCaCrt:   viper.GetString("proxy-prometheus-ca-crt"),
		ProxyHubKey:            viper.GetString("proxy-hub-key"),
		ProxyClusterKey:        viper.GetString("proxy-cluster-key"),
		ProxyProjectKey:        viper.GetString("proxy-project-key"),
	}
	validation_error := validate.Struct(vars)
	if validation_error != nil {
		var invalidValidationError *validator.InvalidValidationError
		if errors.As(validation_error, &invalidValidationError) {
			return fmt.Errorf("Validating the environment variables failed", validation_error)
		}
		var validateErrs validator.ValidationErrors
		if errors.As(validation_error, &validateErrs) {
			return fmt.Errorf("Validating the environment variables failed", validation_error)
		}
	}
	gocloakClient := services.InitializeOauthServer(vars.ProxyAuthBaseUrl, vars.ProxyAuthTlsVerify)

	const proxyPrefix = "proxy"
	proxySrv := cobrautil.HTTPServerFromFlags(cmd, proxyPrefix)
	proxySrv.Handler = logHandler(cors.New(cors.Options{
		AllowedOrigins:   cobrautil.MustGetStringSlice(cmd, "proxy-cors-allowed-origins"),
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
		Debug:            log.Debug().Enabled(),
	}).Handler(
		services.Protect(
			vars.ProxyHubKey,
			vars.ProxyClusterKey,
			vars.ProxyProjectKey,
			gocloakClient,
			vars.ProxyAuthRealm,
			vars.ProxyAuthClientId,
			vars.ProxyAuthClientSecret,
			vars.ProxyAcmHub,
			services.PromQueryHandler(
				gocloakClient,
				vars.ProxyAuthRealm,
				vars.ProxyAuthClientId,
				vars.ProxyPrometheusBaseUrl,
				vars.ProxyPrometheusTlsCert,
				vars.ProxyPrometheusTlsKey,
				vars.ProxyPrometheusCaCrt))))
	go func() {
		if err := cobrautil.HTTPListenFromFlags(cmd, proxyPrefix, proxySrv, zerolog.InfoLevel); err != nil {
			log.Fatal().Err(err).Msg("failed while serving proxy")
		}
	}()
	defer proxySrv.Close()

	signalctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	<-signalctx.Done() // Block until we've received a signal.
	log.Info().Msg("received interrupt signal, exiting gracefully")
	return nil
}
