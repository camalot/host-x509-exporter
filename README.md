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
