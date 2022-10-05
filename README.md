# 🔏 X.509 Certificate Exporter

Inspired by [enix/x509-certificate-exporter](https://github.com/enix/x509-certificate-exporter) but added the ability to just hit a host to get the certificate info

A Prometheus exporter for certificates focusing on expiration monitoring, written in python.


Get notified before they expire:

- configure host name and port

Uses the same dashboard (with tweaks)

![](https://github.com/enix/x509-certificate-exporter/raw/main/docs/grafana-dashboard.jpg)

# METRICS

The following metrics are available:

- `x509_cert_not_before`
- `x509_cert_not_after`
- `x509_cert_expired`
- `x509_read_errors`


# CONFIGURATION

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
```

# USAGE

### DOCKER

```
docker run --rm \
	-p 8932:8932
	-e X509_CONFIG_FILE=/app/config/.configuration.yaml
	-v /mnt/container_data/host-x509-certificate-exporter/config:/app/config
	--restart=unless-stopped
	ghcr.io/camalot/host-x509-exporter:latest
```
### DOCKER COMPOSE

```yaml
host-x509-certificate-exporter:
	image: ghcr.io/camalot/host-x509-exporter:latest
	hostname: host-x509-certificate-exporter
	container_name: host-x509-certificate-exporter
	restart: unless-stopped
	ports:
	- 8932:8932
	networks:
	- internal
	volumes:
	- /mnt/container_data/host-x509-certificate-exporter/config:/app/config
	deploy: {}
	environment: 
		X509_CONFIG_FILE: /app/config/.configuration.yaml
```
