// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/internal/config"
	"github.com/OCP-on-NERC/prom-keycloak-proxy/services"
	"github.com/jzelinskie/cobrautil"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

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
	registerStringFlag(flags, "proxy-prometheus-tls-cert", "", "path at which to find a certificate for prometheus TLS")
	registerStringFlag(flags, "proxy-prometheus-tls-key", "", "path at which to find a private key for prometheus TLS")
	registerStringFlag(flags, "proxy-prometheus-ca-cert", "", "path at which to find a ca certificate for prometheus TLS")
	registerStringFlag(flags, "proxy-hub-key", "", "The hub key to use for auth resources")
	registerStringFlag(flags, "proxy-cluster-key", "", "The cluster key to use for auth resources")
	registerStringFlag(flags, "proxy-project-key", "", "The project key to use for auth resources")

	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func rootRunE(cmd *cobra.Command, args []string) error {
	cfg := config.BuildFromViper(viper.GetViper())
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validating configuration: %w", err)
	}

	gocloakClient := services.InitializeOauthServer(cfg.AuthBaseUrl, cfg.AuthTlsVerify)

	const proxyPrefix = "proxy"
	proxySrv := cobrautil.HTTPServerFromFlags(cmd, proxyPrefix)
	proxySrv.Handler = logHandler(cors.New(cors.Options{
		AllowedOrigins:   cfg.CorsAllowedOrigins,
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
		Debug:            log.Debug().Enabled(),
	}).Handler(
		services.Protect(
			cfg.HubKey,
			cfg.ClusterKey,
			cfg.ProjectKey,
			gocloakClient,
			cfg.AuthRealm,
			cfg.AuthClientId,
			cfg.AuthClientSecret,
			cfg.AcmHub,
			services.PromQueryHandler(
				gocloakClient,
				cfg.AuthRealm,
				cfg.AuthClientId,
				cfg.PrometheusBaseUrl,
				cfg.PrometheusTlsCert,
				cfg.PrometheusTlsKey,
				cfg.PrometheusCaCert,
				cfg.PrometheusToken,
				cfg.AuthTlsVerify))))
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
