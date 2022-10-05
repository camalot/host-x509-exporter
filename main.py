from cryptography import x509
from prometheus_client import start_http_server, Gauge, Enum
import socket
import codecs
import ssl
import sys
import pytz
import yaml
import os
import time
from dotenv import load_dotenv, find_dotenv
import datetime

load_dotenv(find_dotenv())

class AppConfig():
	def __init__(self, file: str):
		try:
			with codecs.open(file, encoding="utf-8-sig", mode="r") as f:
				settings = yaml.safe_load(f)
				self.__dict__.update(settings)
		except yaml.YAMLError as exc:
			print(exc)

class X509Metrics:
	def __init__(self, config):
			self.namespace = "x509"
			self.polling_interval_seconds = config.metrics['pollingInterval']
			self.config = config
			labels = ["host", "issuer_C", "issuer_L", "issuer_O", "issuer_OU", "issuer_ST", "serial_number", "subject_C", "subject_L", "subject_O", "subject_OU", "subject_CN"]
			self.not_valid_after = Gauge(namespace=self.namespace, name=f"cert_not_after", documentation="The timestamp of when the certificate will expire", labelnames=labels)
			self.not_valid_before = Gauge(namespace=self.namespace, name=f"cert_not_before", documentation="The timestamp of when the certificate was issued", labelnames=labels)
			# if expired, set to 1, else 0
			self.expired = Gauge(namespace=self.namespace, name=f"expired", documentation="Indicates if the certificate is currently expired", labelnames=labels)
			self.host_read_errors = Gauge(namespace=self.namespace, name=f"host_read_errors", documentation="Indicates if there was an error reading the certificate", labelnames=["host"])
			self.read_errors = Gauge(namespace=self.namespace, name=f"read_errors", documentation="Indicates if there was an error reading the certificate")

	def run_metrics_loop(self):
		"""Metrics fetching loop"""
		while True:
			print(f"begin metrics fetch")
			self.fetch()
			time.sleep(self.polling_interval_seconds)


	def fetch(self):
		hosts = self.config.hosts
		error_count = 0
		# loop hosts
		for host in hosts:
			try:
				# get host certificate
				cert = ssl.get_server_certificate((host['name'], host['port']))
				# parse certificate
				x509_cert = x509.load_pem_x509_certificate(cert.encode())
				# get expiration date
				expiration_date = x509_cert.not_valid_after.replace(tzinfo=pytz.UTC)
				issued_date = x509_cert.not_valid_before.replace(tzinfo=pytz.UTC)
				serial = x509_cert.serial_number
				issuer = x509_cert.issuer
				# set prometheus metric
				# if has Country_Name (C) attribute
				issuer_C = ""
				if issuer.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME):
					# set issuer_C
					issuer_C = issuer.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value
				# if has Locality_Name (L) attribute
				issuer_L = ""
				if issuer.get_attributes_for_oid(x509.oid.NameOID.LOCALITY_NAME):
					# set issuer_L
					issuer_L = issuer.get_attributes_for_oid(x509.oid.NameOID.LOCALITY_NAME)[0].value
				# if has Organization_Name (O) attribute
				issuer_O = ""
				if issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME):
					# set issuer_O
					issuer_O = issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
				# if has Organizational_Unit_Name (OU) attribute
				issuer_OU = ""
				if issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME):
					# set issuer_OU
					issuer_OU = issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
				# if has State_or_Province_Name (ST) attribute
				issuer_ST = ""
				if issuer.get_attributes_for_oid(x509.oid.NameOID.STATE_OR_PROVINCE_NAME):
					# set issuer_ST
					issuer_ST = issuer.get_attributes_for_oid(x509.oid.NameOID.STATE_OR_PROVINCE_NAME)[0].value
				# if has Common_Name (CN) attribute
				issuer_CN = ""
				if issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
					# set issuer_CN
					issuer_CN = issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
				# if has Country_Name (C) attribute for subject
				subject_C = ""
				if x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME):
					# set subject_C
					subject_C = x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value
				# if has Locality_Name (L) attribute for subject
				subject_L = ""
				if x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.LOCALITY_NAME):
					# set subject_L
					subject_L = x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.LOCALITY_NAME)[0].value
				# if has Organization_Name (O) attribute for subject
				subject_O = ""
				if x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME):
					# set subject_O
					subject_O = x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
				# if has Organizational_Unit_Name (OU) attribute for subject
				subject_OU = ""
				if x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME):
					# set subject_OU
					subject_OU = x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
				# if has State_or_Province_Name (ST) attribute for subject
				subject_ST = ""
				if x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.STATE_OR_PROVINCE_NAME):
					# set subject_ST
					subject_ST = x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.STATE_OR_PROVINCE_NAME)[0].value
				# if has Common_Name (CN) attribute for subject
				subject_CN = ""
				if x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
					# set subject_CN
					subject_CN = x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
				# set prometheus metric
				self.not_valid_after.labels(
					host=f"{host['name']}:{host['port']}",
					issuer_C=issuer_C,
					issuer_L=issuer_L,
					issuer_O=issuer_O,
					issuer_OU=issuer_OU,
					issuer_ST=issuer_ST,
					serial_number=serial,
					subject_C=subject_C,
					subject_L=subject_L,
					subject_O=subject_O,
					subject_OU=subject_OU,
					subject_CN=subject_CN,
					).set(expiration_date.timestamp())
				# set prometheus metric
				self.not_valid_before.labels(
					host=f"{host['name']}:{host['port']}",
					issuer_C=issuer_C,
					issuer_L=issuer_L,
					issuer_O=issuer_O,
					issuer_OU=issuer_OU,
					issuer_ST=issuer_ST,
					serial_number=serial,
					subject_C=subject_C,
					subject_L=subject_L,
					subject_O=subject_O,
					subject_OU=subject_OU,
					subject_CN=subject_CN,
					).set(issued_date.timestamp())
				# set prometheus metric
				self.expired.labels(
					host=f"{host['name']}:{host['port']}",
					issuer_C=issuer_C,
					issuer_L=issuer_L,
					issuer_O=issuer_O,
					issuer_OU=issuer_OU,
					issuer_ST=issuer_ST,
					serial_number=serial,
					subject_C=subject_C,
					subject_L=subject_L,
					subject_O=subject_O,
					subject_OU=subject_OU,
					subject_CN=subject_CN,
				).set(1 if expiration_date < datetime.datetime.now().replace(tzinfo=pytz.UTC) else 0)
			except Exception as e:
				error_count += 1
				self.host_read_errors.labels(host=f"{host['name']}:{host['port']}").set(1)
			if error_count == 0:
				self.host_read_errors.labels(host=f"{host['name']}:{host['port']}").set(0)

		self.read_errors.set(error_count)
def dict_get(dictionary, key, default_value = None):
	if key in dictionary.keys():
		return dictionary[key] or default_value
	else:
		return default_value

def main():
	config_file = dict_get(os.environ, "X509_CONFIG_FILE", default_value="./config/.configuration.yaml")

	config = AppConfig(config_file)

	print(f"start listening on :{config.metrics['port']}")

	app_metrics = X509Metrics(config)
	start_http_server(config.metrics['port'])
	app_metrics.run_metrics_loop()

if __name__ == "__main__":
	main()
