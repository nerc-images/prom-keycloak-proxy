// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/services"
	"github.com/go-playground/validator/v10"
	"github.com/jzelinskie/cobrautil"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type (
	ProxyVars struct {
		ProxyAcmHub             string   `validate:"required,alphanumhyphen,lowercase"`
		ProxyAuthBaseUrl        string   `validate:"required,url"`
		ProxyAuthClientId       string   `validate:"required,alphanumhyphen"`
		ProxyAuthClientSecret   string   `validate:"required,ascii"`
		ProxyAuthRealm          string   `validate:"required,alphanumhyphen"`
		ProxyAuthTlsVerify      bool     `validate:"required"`
		ProxyClusterKey         string   `validate:"required,alphanum"`
		ProxyCorsAllowedOrigins []string `validate:"dive,url|eq=*"`
		ProxyHubKey             string   `validate:"required,alphanum"`
		ProxyProjectKey         string   `validate:"required,alphanum"`
		ProxyPrometheusBaseUrl  string   `validate:"required,url,startswith=http:|startswith=https:"`
		ProxyPrometheusCaCrt    string   `validate:"required,filepath"`
		ProxyPrometheusTlsCert  string   `validate:"required,filepath"`
		ProxyPrometheusTlsKey   string   `validate:"required,filepath"`
	}
)

var validate *validator.Validate

func must(action string, err error) {
	if err != nil {
		log.Fatal().Err(err).Msg(action)
	}
}

func registerStringFlag(flags *pflag.FlagSet, name, defaultValue, usage string) { //nolint:unparam
	flags.String(name, defaultValue, usage)
	must("bind viper to flag", viper.BindPFlag(name, flags.Lookup(name)))
}

func registerStringSliceFlag(flags *pflag.FlagSet, name string, defaultValue []string, usage string) {
	flags.StringSlice(name, defaultValue, usage)
	must("bind viper to flag", viper.BindPFlag(name, flags.Lookup(name)))
}

func registerBoolFlag(flags *pflag.FlagSet, name string, defaultValue bool, usage string) {
	flags.Bool(name, defaultValue, usage)
	must("bind viper to flag", viper.BindPFlag(name, flags.Lookup(name)))
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "prom-keycloak-proxy",
		Short: "Proxy that protects Prometheus queries with Keycloak fine-grained resource permissions",
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

	registerStringSliceFlag(flags, "proxy-cors-allowed-origins", []string{"*"}, "allowed origins for CORS requests")
	registerStringFlag(flags, "proxy-acm-hub", "", "ACM Hub name")
	registerStringFlag(flags, "proxy-auth-client-id", "", "Keycloak auth client ID")
	registerStringFlag(flags, "proxy-auth-client-secret", "", "Keycloak auth client secret")
	registerStringFlag(flags, "proxy-auth-realm", "", "Keycloak auth realm")
	registerStringFlag(flags, "proxy-auth-base-url", "", "Keycloak base URL")
	registerBoolFlag(flags, "proxy-auth-tls-verify", true, "connect to keycloak and verify valid TLS")
	registerStringFlag(flags, "proxy-prometheus-base-url", "", "address of the prometheus to use for checking")
	registerStringFlag(flags, "proxy-prometheus-tls-crt", "", "path at which to find a certificate for prometheus TLS")
	registerStringFlag(flags, "proxy-prometheus-tls-key", "", "path at which to find a private key for prometheus TLS")
	registerStringFlag(flags, "proxy-prometheus-ca-crt", "", "path at which to find a ca certificate for prometheus TLS")
	registerStringFlag(flags, "proxy-hub-key", "", "The hub key to use for auth resources")
	registerStringFlag(flags, "proxy-cluster-key", "", "The cluster key to use for auth resources")
	registerStringFlag(flags, "proxy-project-key", "", "The project key to use for auth resources")

	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("PROM_KEYCLOAK_PROXY")
	viper.AutomaticEnv()

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
	validate = validator.New(validator.WithRequiredStructEnabled())
	must("register alphanumhyphen validator", validate.RegisterValidation("alphanumhyphen", ValidateAlphanumericWithHyphen))

	vars := &ProxyVars{
		ProxyAcmHub:             viper.GetString("proxy-acm-hub"),
		ProxyAuthBaseUrl:        viper.GetString("proxy-auth-base-url"),
		ProxyAuthClientId:       viper.GetString("proxy-auth-client-id"),
		ProxyAuthClientSecret:   viper.GetString("proxy-auth-client-secret"),
		ProxyAuthRealm:          viper.GetString("proxy-auth-realm"),
		ProxyAuthTlsVerify:      viper.GetBool("proxy-auth-tls-verify"),
		ProxyCorsAllowedOrigins: viper.GetStringSlice("proxy-cors-allowed-origins"),
		ProxyClusterKey:         viper.GetString("proxy-cluster-key"),
		ProxyHubKey:             viper.GetString("proxy-hub-key"),
		ProxyProjectKey:         viper.GetString("proxy-project-key"),
		ProxyPrometheusBaseUrl:  viper.GetString("proxy-prometheus-base-url"),
		ProxyPrometheusCaCrt:    viper.GetString("proxy-prometheus-ca-crt"),
		ProxyPrometheusTlsCert:  viper.GetString("proxy-prometheus-tls-crt"),
		ProxyPrometheusTlsKey:   viper.GetString("proxy-prometheus-tls-key"),
	}
	validation_error := validate.Struct(vars)
	if validation_error != nil {
		return fmt.Errorf("validating the configuration failed: %w", validation_error)
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
	defer proxySrv.Close() //nolint:errcheck

	signalctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	<-signalctx.Done() // Block until we've received a signal.
	log.Info().Msg("received interrupt signal, exiting gracefully")
	return nil
}
