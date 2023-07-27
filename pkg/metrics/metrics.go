package metrics

import "github.com/prometheus/client_golang/prometheus"

type MetricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

func (m *MetricInfo) GetPromMetric(value float64, labelValues []string) *prometheus.Metric {
	nm := prometheus.MustNewConstMetric(m.Desc, m.Type, value, labelValues...)
	return &nm
}

func NewMetric(metricName string, docString string, t prometheus.ValueType, namespace string, subsystem string, labelNames []string, constLabels prometheus.Labels) *MetricInfo {
	return &MetricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, metricName),
			docString,
			labelNames,
			constLabels,
		),
		Type: t,
	}
}
