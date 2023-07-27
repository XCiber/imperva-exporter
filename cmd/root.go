/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"github.com/devopsext/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	v "github.com/prometheus/common/version"
	"github.com/xciber/imperva-exporter/pkg/exporter"
	"golang.org/x/exp/slog"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var appName = "IMPERVA_EXPORTER"

func envGet(s string, d interface{}) interface{} {
	return utils.EnvGet(fmt.Sprintf("%s_%s", appName, s), d)
}

var (
	logger      *slog.Logger
	e           *exporter.Exporter
	metricsPort = envGet("LISTEN", ":8080").(string)
	metricsPath = envGet("METRICS", "/metrics").(string)
	debug       = envGet("DEBUG", false).(bool)
	readTimeout = envGet("READ_TIMEOUT", 60).(int)
	timeout     = envGet("TIMEOUT", 15).(int)
	userId      = envGet("ID", "").(string)
	userToken   = envGet("TOKEN", "").(string)
	cacheTtl    = envGet("CACHE_TTL", 240).(int)
)

func root(cmd *cobra.Command, args []string) {
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	if userId == "" || userToken == "" {
		logger.Error("Imperva User ID and Token are required")
		os.Exit(1)
	}

	e = exporter.NewExporter(logger, userId, userToken, timeout, cacheTtl)
	prometheus.MustRegister(e)
	prometheus.MustRegister(v.NewCollector("imperva_exporter"))

	http.Handle(metricsPath, promhttp.Handler())

	srv := &http.Server{
		Addr:        metricsPort,
		ReadTimeout: time.Duration(readTimeout) * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		logger.Error("msg", "Error starting HTTP server", "error", err)
		os.Exit(1)
	}
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "imperva-exporter",
	Short: "Imperva metrics exporter",
	Run:   root,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&metricsPort, "listen", metricsPort, "metrics listen port (default is ':8080')")
	rootCmd.PersistentFlags().StringVar(&metricsPath, "metrics", metricsPath, "metrics path (default is '/metrics')")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", debug, "enable debug loglevel")
	rootCmd.PersistentFlags().IntVar(&readTimeout, "read_timeout", readTimeout, "http server read readTimeout in seconds (default is '15')")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", timeout, "http client timeout in seconds (default is '60')")
	rootCmd.PersistentFlags().IntVar(&cacheTtl, "cache_ttl", cacheTtl, "Imperva Cache TTL in seconds (default is '240')")
}
