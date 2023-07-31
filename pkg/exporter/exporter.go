package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xciber/imperva-exporter/pkg/imperva"
	"golang.org/x/exp/slog"
	"sync"
)

const namespace = "imperva"

type Exporter struct {
	mutex         sync.RWMutex
	totalScrapes  prometheus.Counter
	impervaClient *imperva.Client
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {

	e.impervaClient.DescribeMetrics(ch)

	ch <- e.totalScrapes.Desc()
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.scrape(ch)

	ch <- e.totalScrapes
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) {
	e.totalScrapes.Inc()
	e.impervaClient.GetMetrics(ch)
}

func NewExporter(logger *slog.Logger, id string, secret string, timeout int, ttl int, workers int) *Exporter {
	return &Exporter{
		impervaClient: imperva.NewClient(id, secret, logger, timeout, ttl, workers),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrapes_total",
			Help:      "Current total HAProxy scrapes.",
		}),
	}
}
