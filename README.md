# Imperva Exporter

![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/XCiber/imperva-exporter)](https://goreportcard.com/report/github.com/XCiber/imperva-exporter)

Imperva Exporter is a Prometheus exporter for monitoring Imperva WAF (Web Application Firewall) metrics. It collects data from the Imperva API and exposes it in a format that Prometheus can scrape.

## Table of Contents

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Usage](#usage)
- [Metrics](#metrics)
- [Contributing](#contributing)
- [License](#license)

## Getting Started

### Prerequisites

- Go 1.20 or higher

### Installation

To install the Imperva Exporter, you can use `go get`:

```bash
go get -u github.com/XCiber/imperva-exporter
```

### Configuration

The exporter requires configuration to connect to the Imperva API. You can provide the required configuration through command-line flags or environment variables.

## Usage

```
Usage:
  imperva-exporter [flags]

Flags:
      --cache_ttl int         Cache TTL in seconds, env: IMPERVA_EXPORTER_CACHE_TTL (default 120)
      --clientTimeout int     http client timeout in seconds, env: IMPERVA_EXPORTER_CLIENT_TIMEOUT (default 15)
      --debug                 enable debug loglevel, env: IMPERVA_EXPORTER_DEBUG
  -h, --help                  help for imperva-exporter
      --listen string         metrics listen port, env: IMPERVA_EXPORTER_LISTEN (default ":8080")
      --metrics string        metrics path, env: IMPERVA_EXPORTER_METRICS (default "/metrics")
      --read_timeout int      http server read timeout in seconds, env: IMPERVA_EXPORTER_SERVER_TIMEOUT (default 60)
      --update_interval int   Imperva update interval in seconds, env: IMPERVA_EXPORTER_UPDATE_INTERVAL (default 60)
  -v, --version               version for imperva-exporter
      --workers int           Initial query workers, env: IMPERVA_EXPORTER_WORKERS (default 5)
```



By default, exporter will start serving metrics at `http://0.0.0.0:8080/metrics`.

## Metrics

The Imperva Exporter provides the following Prometheus metrics:

- `imperva_up` - Last scrape of Imperva was successful
- `imperva_waf_ddos_threshold` - DDoS threshold
- `imperva_stats_bandwidth` - Bandwidth
- `imperva_stats_bps` - Bits per second
- `imperva_stats_hits_human` - Human requests
- `imperva_stats_hits_human_rps` - Human requests per second
- `imperva_stats_hits_bot` - Bot requests
- `imperva_stats_hits_bot_rps` - Bot requests per second
- `imperva_stats_hits_blocked` - Blocked requests
- `imperva_stats_hits_blocked_rps` - Blocked requests per second
- `imperva_stats_visits_human` - Human visits
- `imperva_stats_visits_bot` - Bot visits
- `imperva_stats_geo_dc` - Requests by data-center location
- `imperva_stats_visits_country` - Visits by country
- `imperva_stats_visits_client` - Visits by client application

## Contributing

Contributions are welcome! If you find any issues or want to add new features, please feel free to open an issue or submit a pull request.

Before submitting a pull request, please make sure to follow the [CONTRIBUTING.md](./CONTRIBUTING.md) guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.