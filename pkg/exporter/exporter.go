package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xciber/imperva-exporter/pkg/imperva"
	"golang.org/x/exp/slog"
	"sync"
	"time"
)

const namespace = "imperva"

type Exporter struct {
	mutex         sync.RWMutex
	totalScrapes  prometheus.Counter
	impervaClient *imperva.Client
	logger        *slog.Logger
	metricsState  map[string][]*prometheus.Metric
}

type workerResult struct {
	domain  string
	metrics []*prometheus.Metric
}

func (e *Exporter) Worker(jobs <-chan string, results chan<- *workerResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for j := range jobs {
		e.logger.Debug("Getting metrics for domain", "domain", j)
		m, err := e.impervaClient.GetMetricsByDomain(j)
		if err != nil {
			e.logger.Error("Error getting metrics", "error", err)
			continue
		}
		results <- &workerResult{domain: j, metrics: m}
	}
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

func (e *Exporter) RunUpdater(interval time.Duration) {
	t := time.NewTicker(interval * time.Second)
	inWork := false
	go func(t *time.Ticker) {
		for {
			<-t.C
			if inWork {
				e.logger.Warn("Previous scrape still in progress, skipping")
				continue
			}
			inWork = true
			e.mutex.Lock()
			err := e.impervaClient.UpdateSiteList()
			e.mutex.Unlock()
			if err != nil {
				e.logger.Error("Error getting site list", "error", err)
			}
			for domain := range e.impervaClient.Sites {
				m, err := e.impervaClient.GetMetricsByDomain(domain)
				if err != nil {
					e.logger.Error("Error getting metric", "domain", domain, "error", err)
				}
				e.mutex.Lock()
				e.metricsState[domain] = m
				e.mutex.Unlock()
			}
			inWork = false
		}
	}(t)

}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) {
	e.totalScrapes.Inc()
	for _, metrics := range e.metricsState {
		for _, m := range metrics {
			ch <- *m
		}
	}
}

func NewExporter(logger *slog.Logger, id string, secret string, timeout int, ttl int, workers int) *Exporter {
	e := &Exporter{
		logger:        logger,
		metricsState:  make(map[string][]*prometheus.Metric),
		impervaClient: imperva.NewClient(id, secret, logger, timeout, ttl),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrapes_total",
			Help:      "Current total HAProxy scrapes.",
		}),
	}

	// Initial scrape in parallel
	jobs := make(chan string, len(e.impervaClient.Sites))
	results := make(chan *workerResult, 5*workers)

	wg := new(sync.WaitGroup)
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go e.Worker(jobs, results, wg)
	}

	for domain := range e.impervaClient.Sites {
		jobs <- domain
	}

	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		e.metricsState[result.domain] = result.metrics
	}

	return e
}
