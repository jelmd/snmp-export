# Prometheus SNMP Exporter

This repository is a fork of the [Prometheus SNMP Exporter](https://github.com/prometheus/snmp_exporter), an SNMP agent which exposes queried data in [Prometheuse exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/) per default using the endpoint URL http://_hostname:9116i_/snmp?target=_snmpServer_ (port and IP are customizable of course) and thus visualized e.g. using [Grafana](https://grafana.com/), [Netdata](https://www.netdata.cloud/), or [Zabbix](https://www.zabbix.com/).

The configuration for the exporter can be generated using the included
[generator](generator/) (which depends on NetSNMP).

For more details wrt. installation, how to build, possible prometheus client configuration, etc. see https://github.com/prometheus/snmp\_exporter .

# Enhancements
For now the main enhancements wrt. to the original repo alias upstream are:
- better [documentation](generator/) of the generator file format and implications to the exporter.
- allows a much more fine grained configuration of emitted metrics, its label names and label values.
- better CLI support.

It follows the main motto: Tackle the root cause of inefficiency (e.g. do not compose/emit data no one needs) instead of the symptoms (e.g. with prometheus client relabeling) and thus saving a lot of ressources and finally energy.

To get an impression how far more or less interested people can get, have a look at the [generator file](generator/generator.cisco.yml) we use to produce our production exporter configuration file (snippet) wrt. our Cisco equipment.
