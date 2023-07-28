package imperva

import (
	"encoding/json"
	"fmt"
	"github.com/kofalt/go-memoize"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xciber/imperva-exporter/pkg/metrics"
	"golang.org/x/exp/slog"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	baseApiUrl       = "https://my.incapsula.com/api/"
	siteListEndpoint = "prov/v1/sites/list"
	statsApiEndpoint = "stats/v1"
)

type Client struct {
	httpClient   *http.Client
	logger       *slog.Logger
	clientId     string
	clientSecret string
	sites        *SiteListResponse
	cache        *memoize.Memoizer
	metrics      map[string]*metrics.MetricInfo
}

type SiteListResponse struct {
	Sites []struct {
		SiteId               int      `json:"site_id"`
		Status               string   `json:"status"`
		Domain               string   `json:"domain"`
		AccountId            int      `json:"account_id"`
		AccelerationLevel    string   `json:"acceleration_level"`
		AccelerationLevelRaw string   `json:"acceleration_level_raw"`
		SiteCreationDate     int64    `json:"site_creation_date"`
		Ips                  []string `json:"ips"`
		//Dns                  []struct {
		//	DnsRecordName string   `json:"dns_record_name"`
		//	SetTypeTo     string   `json:"set_type_to"`
		//	SetDataTo     []string `json:"set_data_to"`
		//} `json:"dns"`
		//OriginalDns []struct {
		//	DnsRecordName string   `json:"dns_record_name"`
		//	SetTypeTo     string   `json:"set_type_to"`
		//	SetDataTo     []string `json:"set_data_to"`
		//} `json:"original_dns"`
		//Warnings []interface{} `json:"warnings"`
		Active                               string `json:"active"`
		SupportAllTlsVersions                bool   `json:"support_all_tls_versions"`
		UseWildcardSanInsteadOfFullDomainSan bool   `json:"use_wildcard_san_instead_of_full_domain_san"`
		AddNakedDomainSan                    bool   `json:"add_naked_domain_san"`
		//AdditionalErrors                     []interface{} `json:"additionalErrors"`
		DisplayName string `json:"display_name"`
		Security    struct {
			Waf struct {
				Rules []struct {
					Action                 string `json:"action,omitempty"`
					ActionText             string `json:"action_text,omitempty"`
					Id                     string `json:"id"`
					Name                   string `json:"name"`
					BlockBadBots           bool   `json:"block_bad_bots,omitempty"`
					ChallengeSuspectedBots bool   `json:"challenge_suspected_bots,omitempty"`
					ActivationMode         string `json:"activation_mode,omitempty"`
					ActivationModeText     string `json:"activation_mode_text,omitempty"`
					DdosTrafficThreshold   int    `json:"ddos_traffic_threshold,omitempty"`
				} `json:"rules"`
			} `json:"waf"`
		} `json:"security"`
		//SealLocation struct {
		//	Id   string `json:"id"`
		//	Name string `json:"name"`
		//} `json:"sealLocation"`
		//Ssl struct {
		//	OriginServer struct {
		//		Detected        bool   `json:"detected"`
		//		DetectionStatus string `json:"detectionStatus"`
		//	} `json:"origin_server"`
		//	CustomCertificate struct {
		//		Active                bool   `json:"active"`
		//		ExpirationDate        int64  `json:"expirationDate,omitempty"`
		//		RevocationError       bool   `json:"revocationError,omitempty"`
		//		ValidityError         bool   `json:"validityError,omitempty"`
		//		ChainError            bool   `json:"chainError,omitempty"`
		//		HostnameMismatchError bool   `json:"hostnameMismatchError,omitempty"`
		//		FingerPrint           string `json:"fingerPrint,omitempty"`
		//		SerialNumber          string `json:"serialNumber,omitempty"`
		//		Hsm                   string `json:"hsm,omitempty"`
		//		InputHash             string `json:"inputHash,omitempty"`
		//	} `json:"custom_certificate"`
		//	GeneratedCertificate struct {
		//		Ca               string      `json:"ca"`
		//		ValidationMethod string      `json:"validation_method"`
		//		ValidationData   interface{} `json:"validation_data"`
		//		San              []string    `json:"san"`
		//		ValidationStatus string      `json:"validation_status"`
		//		OrderId          string      `json:"orderId"`
		//		ExpirationDate   int64       `json:"expirationDate"`
		//	} `json:"generated_certificate"`
		//} `json:"ssl"`
		//SiteDualFactorSettings struct {
		//	SpecificUsers []string `json:"specificUsers"`
		//	Enabled       bool     `json:"enabled"`
		//	CustomAreas   []struct {
		//		Pattern string `json:"pattern"`
		//		Url     string `json:"url"`
		//	} `json:"customAreas"`
		//	CustomAreasExceptions        []interface{} `json:"customAreasExceptions"`
		//	AllowAllUsers                bool          `json:"allowAllUsers"`
		//	ShouldSuggestApplicatons     bool          `json:"shouldSuggestApplicatons"`
		//	AllowedMedia                 []string      `json:"allowedMedia"`
		//	ShouldSendLoginNotifications bool          `json:"shouldSendLoginNotifications"`
		//	Version                      int           `json:"version"`
		//} `json:"siteDualFactorSettings"`
		//LoginProtect struct {
		//	Enabled           bool `json:"enabled"`
		//	SpecificUsersList []struct {
		//		Email  string `json:"email"`
		//		Name   string `json:"name"`
		//		Status string `json:"status"`
		//	} `json:"specific_users_list"`
		//	SendLpNotifications   bool     `json:"send_lp_notifications"`
		//	AllowAllUsers         bool     `json:"allow_all_users"`
		//	AuthenticationMethods []string `json:"authentication_methods"`
		//	Urls                  []string `json:"urls"`
		//	UrlPatterns           []string `json:"url_patterns"`
		//} `json:"login_protect"`
		//PerformanceConfiguration struct {
		//	AdvancedCachingRules struct {
		//		NeverCacheResources []struct {
		//			Pattern string `json:"pattern"`
		//			Url     string `json:"url"`
		//		} `json:"never_cache_resources"`
		//		AlwaysCacheResources []interface{} `json:"always_cache_resources"`
		//	} `json:"advanced_caching_rules"`
		//	AccelerationLevel         string `json:"acceleration_level"`
		//	AccelerationLevelRaw      string `json:"acceleration_level_raw"`
		//	AsyncValidation           bool   `json:"async_validation"`
		//	MinifyJavascript          bool   `json:"minify_javascript"`
		//	MinifyCss                 bool   `json:"minify_css"`
		//	MinifyStaticHtml          bool   `json:"minify_static_html"`
		//	CompressJpeg              bool   `json:"compress_jpeg"`
		//	CompressJepg              bool   `json:"compress_jepg"`
		//	ProgressiveImageRendering bool   `json:"progressive_image_rendering"`
		//	AggressiveCompression     bool   `json:"aggressive_compression"`
		//	CompressPng               bool   `json:"compress_png"`
		//	OnTheFlyCompression       bool   `json:"on_the_fly_compression"`
		//	TcpPrePooling             bool   `json:"tcp_pre_pooling"`
		//	ComplyNoCache             bool   `json:"comply_no_cache"`
		//	ComplyVary                bool   `json:"comply_vary"`
		//	UseShortestCaching        bool   `json:"use_shortest_caching"`
		//	PerferLastModified        bool   `json:"perfer_last_modified"`
		//	PreferLastModified        bool   `json:"prefer_last_modified"`
		//	DisableClientSideCaching  bool   `json:"disable_client_side_caching"`
		//	Cache300X                 bool   `json:"cache300x"`
		//	CacheHeaders              []struct {
		//		HeaderName string `json:"headerName"`
		//	} `json:"cache_headers"`
		//} `json:"performance_configuration"`
		//ExtendedDdos int    `json:"extended_ddos"`
		//LogLevel     string `json:"log_level,omitempty"`
		//IncapRules   []struct {
		//	Id           int    `json:"id"`
		//	Name         string `json:"name"`
		//	Action       string `json:"action"`
		//	Rule         string `json:"rule"`
		//	CreationDate int64  `json:"creation_date"`
		//} `json:"incap_rules"`
		//RestrictedCnameReuse bool   `json:"restricted_cname_reuse"`
		//Res                  int    `json:"res"`
		//ResMessage           string `json:"res_message"`
		//DebugInfo            struct {
		//	IdInfo string `json:"id-info"`
		//} `json:"debug_info"`
	} `json:"sites"`
	Res        int    `json:"res"`
	ResMessage string `json:"res_message"`
	DebugInfo  struct {
		IdInfo string `json:"id-info"`
	} `json:"debug_info"`
}

type TSData struct {
	Data [][]int64 `json:"data"`
	Id   string    `json:"id"`
	Name string    `json:"name"`
}

type StatsTimeSeriesResponse struct {
	BandwidthTimeseries []TSData `json:"bandwidth_timeseries"`
	VisitsTimeseries    []TSData `json:"visits_timeseries"`
	HitsTimeseries      []TSData `json:"hits_timeseries"`
	Res                 int      `json:"res"`
	ResMessage          string   `json:"res_message"`
	DebugInfo           struct {
		IdInfo string `json:"id-info"`
	} `json:"debug_info"`
}

type StatsSummaryResponse struct {
	RequestsGeoDistSummary struct {
		Data [][]interface{} `json:"data"`
		Id   string          `json:"id"`
		Name string          `json:"name"`
	} `json:"requests_geo_dist_summary"`
	VisitsDistSummary []struct {
		Data [][]interface{} `json:"data"`
		Id   string          `json:"id"`
		Name string          `json:"name"`
	} `json:"visits_dist_summary"`
	Res        int    `json:"res"`
	ResMessage string `json:"res_message"`
	DebugInfo  struct {
		IdInfo string `json:"id-info"`
	} `json:"debug_info"`
}

func (c *Client) post(path string) ([]byte, error) {
	return c.postWithParams(path, nil)
}

func (c *Client) postWithParams(path string, param map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, baseApiUrl+path, nil)
	if err != nil {
		c.logger.Error("Error creating request", "error", err)
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("x-API-Id", c.clientId)
	req.Header.Add("x-API-Key", c.clientSecret)

	p := req.URL.Query()
	for k, v := range param {
		p[k] = append(p[k], v)
	}

	req.URL.RawQuery = p.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("Error sending request", "error", err)
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			c.logger.Error("Error closing response body", "error", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		c.logger.Error("Error response from server", "status", resp.Status)
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Error("Error reading response body", "error", err)
		return nil, err
	}

	return body, nil
}

func (c *Client) GetMetrics(ch chan<- prometheus.Metric) {
	up := 1.0
	ml := make([]*prometheus.Metric, 0)

	wafMetrics, err := c.getSitesWafMetrics()
	if err != nil {
		up = 0.0
	} else {
		ml = append(ml, wafMetrics...)
	}

	statsMetrics, err := c.getStatsTimeSeriesMetrics()
	if err != nil {
		up = 0.0
	} else {
		ml = append(ml, statsMetrics...)
	}

	ml = append(ml, c.metrics["up"].GetPromMetric(up, nil))

	for _, m := range ml {
		ch <- *m
	}
}

func (c *Client) DescribeMetrics(ch chan<- *prometheus.Desc) {
	for _, m := range c.metrics {
		ch <- m.Desc
	}
}

func (c *Client) updateSiteList() error {

	c.logger.Debug("updating site list")

	siteList, err, cached := c.cache.Memoize("siteList",
		func() (interface{}, error) {
			return c.post(siteListEndpoint)
		})
	if err != nil {
		return err
	}

	c.logger.Debug("ddos call", "cached", cached)

	sr := &SiteListResponse{}
	err = json.Unmarshal(siteList.([]byte), sr)
	if err != nil {
		c.logger.Error("Error unmarshalling response", "error", err)
		return err
	}

	c.sites = sr

	return nil
}

func (c *Client) getSitesWafMetrics() ([]*prometheus.Metric, error) {

	c.logger.Debug("getting sites waf metrics")

	res := make([]*prometheus.Metric, 0)

	err := c.updateSiteList()
	if err != nil {
		c.logger.Error("Error updating site list", "error", err)
		return nil, err
	}

	for _, site := range c.sites.Sites {
		for _, rule := range site.Security.Waf.Rules {
			if rule.Id == "api.threats.ddos" {
				res = append(res, c.metrics["ddos_threshold"].GetPromMetric(float64(rule.DdosTrafficThreshold), []string{site.Domain, rule.ActivationModeText}))
			}
		}
	}

	return res, nil
}

func (c *Client) tsdToMetric(domain string, tsData TSData) (*prometheus.Metric, error) {
	// we relay that values are sorted by time, and we take
	// one point before the last one for each time series
	// because the last one is not complete
	// so data will be 5 minutes (one bucket) late
	// in future we will try to scape last point diffs
	// to get a more accurate value
	t := len(tsData.Data) - 2
	if t < 0 {
		return nil, fmt.Errorf("no data for metric %s", tsData.Id)
	}

	if len(tsData.Data[t]) != 2 {
		return nil, fmt.Errorf("wrong number of data for metric %s", tsData.Id)
	}

	switch tsData.Id {
	case "api.stats.bandwidth_timeseries.bandwidth":
		return c.metrics["bandwidth"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	case "api.stats.bandwidth_timeseries.bps":
		return c.metrics["bps"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	case "api.stats.hits_timeseries.human":
		return c.metrics["hits_human"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	case "api.stats.hits_timeseries.human_ps":
		return c.metrics["hits_human_rps"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	case "api.stats.hits_timeseries.bot":
		return c.metrics["hits_bot"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	case "api.stats.hits_timeseries.bot_ps":
		return c.metrics["hits_bot_rps"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	case "api.stats.hits_timeseries.blocked":
		return c.metrics["hits_blocked"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	case "api.stats.hits_timeseries.blocked_ps":
		return c.metrics["hits_blocked_rps"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	case "api.stats.visits_timeseries.human":
		return c.metrics["visits_human"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	case "api.stats.visits_timeseries.bot":
		return c.metrics["visits_bot"].GetPromMetric(float64(tsData.Data[t][1]), []string{domain}), nil
	default:
		return nil, fmt.Errorf("unknown metric %s", tsData.Id)
	}
}

type TSWorkerData struct {
	domain string
	siteId int
}

func (c *Client) tsWorker(id int, input <-chan TSWorkerData, output chan<- *prometheus.Metric, wg *sync.WaitGroup) {

	defer wg.Done()

	c.logger.Debug("starting ts worker", "id", id)

	for data := range input {
		c.logger.Debug("worker gets site ts metrics", "id", id, "domain", data.domain)
		c.getSiteTSMetrics(output, data.domain, data.siteId)
	}

	c.logger.Debug("worker finished processing input", "id", id)
}

func (c *Client) getSiteTSMetrics(ch chan<- *prometheus.Metric, domain string, siteId int) {

	c.logger.Debug("getting site ts metrics", "domain", domain)
	data, err, cached := c.cache.Memoize("TimeSeries_"+domain,
		func() (interface{}, error) {
			return c.postWithParams(
				statsApiEndpoint,
				map[string]string{
					"site_id":     strconv.Itoa(siteId),
					"stats":       "bandwidth_timeseries,hits_timeseries,visits_timeseries",
					"time_range":  "today",
					"granularity": "300000",
				})
		})
	if err != nil {
		c.logger.Error("Error getting time series", "domain", domain, "error", err)
		return
	}
	c.logger.Debug("got site ts metrics", "domain", domain, "cached", cached)

	tsr := &StatsTimeSeriesResponse{}
	err = json.Unmarshal(data.([]byte), tsr)
	if err != nil {
		c.logger.Error("Error unmarshalling response", "domain", domain, "error", err)
		return
	}

	c.logger.Debug("metrics unmarshalled", "domain", domain)

	for _, tsData := range tsr.BandwidthTimeseries {
		m, err := c.tsdToMetric(domain, tsData)
		if err != nil {
			c.logger.Error("Error converting time series data to metric", "error", err)
			continue
		}
		ch <- m
	}
	c.logger.Debug("bandwidth metrics sent", "domain", domain)

	for _, tsData := range tsr.HitsTimeseries {
		m, err := c.tsdToMetric(domain, tsData)
		if err != nil {
			c.logger.Error("Error converting time series data to metric", "error", err)
			continue
		}
		ch <- m
	}
	c.logger.Debug("hits metrics sent", "domain", domain)

	for _, tsData := range tsr.VisitsTimeseries {
		m, err := c.tsdToMetric(domain, tsData)
		if err != nil {
			c.logger.Error("Error converting time series data to metric", "error", err)
			continue
		}
		ch <- m
	}
	c.logger.Debug("visits metrics sent", "domain", domain)
}

func (c *Client) getStatsTimeSeriesMetrics() ([]*prometheus.Metric, error) {

	c.logger.Debug("getting stats time series metrics")

	// TODO: make this configurable
	numWorkers := 5

	inputCh := make(chan TSWorkerData)

	resultCh := make(chan *prometheus.Metric, len(c.metrics)*len(c.sites.Sites))

	wg := new(sync.WaitGroup)
	wg.Add(numWorkers)

	for i := 0; i < numWorkers; i++ {
		go c.tsWorker(i, inputCh, resultCh, wg)
	}

	for _, site := range c.sites.Sites {
		inputCh <- TSWorkerData{
			domain: site.Domain,
			siteId: site.SiteId,
		}
	}

	close(inputCh)
	c.logger.Debug("input channel closed")

	wg.Wait()
	c.logger.Debug("All workers finished")

	close(resultCh)
	c.logger.Debug("result channel closed")

	res := make([]*prometheus.Metric, 0)
	for r := range resultCh {
		res = append(res, r)
	}

	return res, nil
}

func NewClient(id string, secret string, logger *slog.Logger, timeout int, ttl int) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		logger:       logger,
		clientId:     id,
		clientSecret: secret,
		metrics:      make(map[string]*metrics.MetricInfo),
		cache:        memoize.NewMemoizer(time.Duration(ttl)*time.Second, time.Minute),
		sites:        &SiteListResponse{},
	}

	// declare metrics
	c.metrics["up"] = metrics.NewMetric("up", "Was the last scrape of Imperva successful.", prometheus.GaugeValue, "imperva", "", nil, nil)
	c.metrics["ddos_threshold"] = metrics.NewMetric("ddos_threshold", "DDoS Threshold", prometheus.GaugeValue, "imperva", "waf", []string{"domain", "mode"}, nil)
	c.metrics["bandwidth"] = metrics.NewMetric("bandwidth", "Site bandwidth", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)
	c.metrics["bps"] = metrics.NewMetric("bps", "Site bandwidth in bps", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)
	c.metrics["hits_human"] = metrics.NewMetric("hits_human", "Site hits from humans", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)
	c.metrics["hits_human_rps"] = metrics.NewMetric("hits_human_rps", "Site hits from humans per second", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)
	c.metrics["hits_bot"] = metrics.NewMetric("hits_bot", "Site hits from bots", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)
	c.metrics["hits_bot_rps"] = metrics.NewMetric("hits_bot_rps", "Site hits from bots per second", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)
	c.metrics["hits_blocked"] = metrics.NewMetric("hits_blocked", "Site hits blocked", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)
	c.metrics["hits_blocked_rps"] = metrics.NewMetric("hits_blocked_rps", "Site hits blocked per second", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)
	c.metrics["visits_human"] = metrics.NewMetric("visits_human", "Site visits from humans", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)
	c.metrics["visits_bot"] = metrics.NewMetric("visits_bot", "Site visits from bots", prometheus.GaugeValue, "imperva", "stats", []string{"domain"}, nil)

	return c
}
