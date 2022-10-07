# 🔏 X.509 CERTIFICATE EXPORTER

[![Host-X509-Certificate-Exporter Publish](https://github.com/camalot/host-x509-certificate-exporter/actions/workflows/publish-main.yml/badge.svg)](https://github.com/camalot/host-x509-certificate-exporter/actions/workflows/publish-main.yml) [![License](https://img.shields.io/github/license/camalot/host-x509-certificate-exporter.svg)](https://github.com/camalot/host-x509-certificate-exporter/blob/master/LICENSE) [![Version](https://badge.fury.io/gh/camalot%2Fhost-x509-certificate-exporter.svg)](https://github.com/camalot/host-x509-certificate-exporter/pkgs/container/host-x509-certificate-exporter)

Inspired by [enix/x509-certificate-exporter](https://github.com/enix/x509-certificate-exporter) but added the ability to just hit a host to get the certificate info. If you want to export certs from kubernetes or from local files, see the exporter from enix. This is only if you want to get the cert from the host and port. 

This uses all the same metric names. Most of the labels are the same, this just adds a `host` label.

A Prometheus exporter for certificates focusing on expiration monitoring, written in python.


Get notified before they expire:

- configure host name and port of the endpoint to test

Uses the same dashboard (with tweaks) 

![](https://i.imgur.com/UWy29Rr.png)

# METRICS

The following metrics are available:

- `x509_cert_not_before`
- `x509_cert_not_after`
- `x509_cert_expired`
- `x509_read_errors`
- `x509_host_read_errors`
- `x509_build_info`


# CONFIGURATION

## CONFIG FILE

By default, it will load `/app/config/.configuration.yaml`. To change this, set the `X509_CONFIG_FILE` environment variable.

```yaml
metrics:
  # port to listen on for exporting
  port: 8932
  # how often to poll the certificates
  pollingInterval: 43200 # 12 hours
# hosts to check
hosts:
- name: server1.home.local
  port: 443
- name: server2.home.local
  port: 8443
- name: server3.home.local
  port: 10000
# add labels to the metric
labels:
- name: "my-label"
  value: "foo-bar"
```

## ENVIRONMENT VARIABLES

You can set all the configuration via environment variables, if needed.

- `X509_CONFIG_FILE`: Path to the config file to load `default: /app/config/.configuration.yaml`
- `X509_CONFIG_METRICS_PORT`: port to listen on for exporting. `default: 8932`
- `X509_CONFIG_METRICS_POLLING_INTERVAL`: how often to poll the certificates. `default: 43200`
- `X509_CONFIG_HOST_<NUMBER>`: Host and port to check. `X509_CONFIG_HOST_1=server1.home.local:443`
- `X509_CONFIG_LABEL_<NAME>`: Add custom labels and values to the metrics. `<NAME>` must match `([A-Z0-9_-]+)`. The label will be lowercase in the metric. All labels will be added to all host metrics. 

If you only want to configure via environment variables, then set `X509_CONFIG_FILE` to a non-existent file. `/app/config/null.yaml`. 

# USAGE

## DOCKER

```
docker run --rm \
	-p 8932:8932 \
	-e X509_CONFIG_FILE=/app/config/.configuration.yaml \
	-e X509_CONFIG_METRICS_PORT=8932 \
	-e X509_CONFIG_METRICS_POLLING_INTERVAL=43200 \
	-e X509_CONFIG_HOST_1=host1.home.local:443 \
	-e X509_CONFIG_HOST_2=host2.home.local:443 \
	-e X509_CONFIG_LABEL_ENV=dev \
	-v /mnt/container_data/host-x509-certificate-exporter/config:/app/config \
	--restart=unless-stopped \
	ghcr.io/camalot/host-x509-certificate-exporter:latest
```
## DOCKER COMPOSE

```yaml
version: '3.7'
services:
  host-x509-certificate-exporter:
    image: ghcr.io/camalot/host-x509-certificate-exporter:latest
    hostname: host-x509-certificate-exporter
    container_name: host-x509-certificate-exporter
    restart: unless-stopped
    network_mode: bridge
    ports:
    - 8932:8932
    volumes:
    - /path/to/config:/app/config
    environment:
      X509_CONFIG_FILE: /app/config/.configuration.yaml
      X509_CONFIG_METRICS_PORT: "8932"
      X509_CONFIG_METRICS_POLLING_INTERVAL: "43200"
      X509_CONFIG_HOST_1: host1.home.local:443
      X509_CONFIG_HOST_2: host2.home.local:443
      X509_CONFIG_LABEL_ENV: dev
```

# PROMETHEUS ALERTS

```yaml
rules:
- alert: X509ExporterReadErrors
  annotations:
    description: Over the last 15 minutes, this host-x509-certificate-exporter instance has experienced errors reading certificate files or querying the Kubernetes API. This could be caused by a misconfiguration if triggered when the exporter starts.
    summary: Increasing read errors for host-x509-certificate-exporter
  expr: delta(x509_read_errors[15m]) > 0
  for: 5m
  labels:
    severity: warning
- alert: CertificateRenewal
  annotations:
    description: | 
      Certificate for "{{ $labels.subject_CN }}" should be renewed
      {{if $labels.secret_name }}in Kubernets secret "{{ $labels.secret_namespace
      }}/{{ $labels.secret_name }}"{{else}}at location "{{ $labels.filepath }}"{{end}}
    summary: Certificate should be renewed
  expr: ((x509_cert_not_after - time()) / 86400) < 28
  for: 15m
  labels:
    severity: warning
- alert: CertificateExpiration
  annotations:
    description: |
      Certificate for "{{ $labels.subject_CN }}" is about to expire
      {{if $labels.secret_name }}in Kubernets secret "{{ $labels.secret_namespace
      }}/{{ $labels.secret_name }}"{{else}}at location "{{ $labels.filepath }}"{{end}}
    summary: Certificate is about to expire
  expr: ((x509_cert_not_after - time()) / 86400) < 14
  for: 15m
  labels:
    severity: critical
```