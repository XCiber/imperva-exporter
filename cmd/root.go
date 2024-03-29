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

var (
	appName = "IMPERVA_EXPORTER"
	version = "undefined"
)

func envGet(s string, d interface{}) interface{} {
	return utils.EnvGet(fmt.Sprintf("%s_%s", appName, s), d)
}

var (
	logger         *slog.Logger
	e              *exporter.Exporter
	metricsPort    = envGet("LISTEN", ":8080").(string)
	metricsPath    = envGet("METRICS", "/metrics").(string)
	debug          = envGet("DEBUG", false).(bool)
	serverTimeout  = envGet("SERVER_TIMEOUT", 60).(int)
	clientTimeout  = envGet("CLIENT_TIMEOUT", 15).(int)
	apiId          = envGet("API_ID", "").(string)
	apiKey         = envGet("API_KEY", "").(string)
	cacheTtl       = envGet("CACHE_TTL", 120).(int)
	workers        = envGet("WORKERS", 5).(int)
	updateInterval = envGet("UPDATE_INTERVAL", 60).(int)
)

func root(cmd *cobra.Command, args []string) {
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	if apiId == "" || apiKey == "" {
		logger.Error("Imperva API ID and Key are required")
		os.Exit(1)
	}

	e = exporter.NewExporter(logger, apiId, apiKey, clientTimeout, cacheTtl, workers)
	prometheus.MustRegister(e)
	prometheus.MustRegister(v.NewCollector("imperva_exporter"))

	http.Handle(metricsPath, promhttp.Handler())

	srv := &http.Server{
		Addr:        metricsPort,
		ReadTimeout: time.Duration(serverTimeout) * time.Second,
	}

	e.RunUpdater(time.Duration(updateInterval))

	if err := srv.ListenAndServe(); err != nil {
		logger.Error("msg", "Error starting HTTP server", "error", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:     "imperva-exporter",
	Short:   "Imperva metrics exporter",
	Version: version,
	Run:     root,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&metricsPort, "listen", metricsPort, "metrics listen port, env: IMPERVA_EXPORTER_LISTEN")
	rootCmd.PersistentFlags().StringVar(&metricsPath, "metrics", metricsPath, "metrics path, env: IMPERVA_EXPORTER_METRICS")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", debug, "enable debug loglevel, env: IMPERVA_EXPORTER_DEBUG")
	rootCmd.PersistentFlags().IntVar(&serverTimeout, "read_timeout", serverTimeout, "http server read timeout in seconds, env: IMPERVA_EXPORTER_SERVER_TIMEOUT")
	rootCmd.PersistentFlags().IntVar(&clientTimeout, "clientTimeout", clientTimeout, "http client timeout in seconds, env: IMPERVA_EXPORTER_CLIENT_TIMEOUT")
	rootCmd.PersistentFlags().IntVar(&cacheTtl, "cache_ttl", cacheTtl, "Cache TTL in seconds, env: IMPERVA_EXPORTER_CACHE_TTL")
	rootCmd.PersistentFlags().IntVar(&workers, "workers", workers, "Initial query workers, env: IMPERVA_EXPORTER_WORKERS")
	rootCmd.PersistentFlags().IntVar(&updateInterval, "update_interval", updateInterval, "Imperva update interval in seconds, env: IMPERVA_EXPORTER_UPDATE_INTERVAL")
}
