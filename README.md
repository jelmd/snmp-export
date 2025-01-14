# Prometheus SNMP Exporter

This repository is a fork of the [Prometheus SNMP Exporter](https://github.com/prometheus/snmp_exporter), an SNMP agent which exposes queried data in [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/) per default using the endpoint URL http://_hostname:9116_/snmp?target=_snmpServer_ (port and IP are customizable of course) and thus visualized e.g. using [Grafana](https://grafana.com/), [Netdata](https://www.netdata.cloud/), or [Zabbix](https://www.zabbix.com/).

The configuration for the exporter can be generated using the included
generator [snmp-export-cfg](generator/) (which depends on NetSNMP). It solves a lot of
configuration problems in advance, and allows the exporter to work efficiently
and independently of any SNMP libraries and tools.

# Enhancements
For now the main enhancements wrt. to the original repo alias upstream is the suport of:
- better [documentation](generator/) of the generator file format and implications to the exporter.
- a much more fine grained configuration of emitted metrics, its label names and label values
- dropping a metric based on regex match of its label value(s)
- replacing the metric name based on its value regex match or sub OID
- dropping labels based on label value regex match
- remapping metric as well as label values
- generic overrides, walks, metric narrowing via brace expansion
- non-numeric override regex\_extracts results, i.e. consistent behavior as without an override: for non-float values insert a label=value pair and set metric value = 1.0.
- counter, gauge, Float, DateAndTime in override regex\_extracts (value gets converted to its decimal string representation first). So no need to force its type to e.g. DisplayString anymore, which would in turn cause its value to be set to 1.0.
- injection of non-index based labels and related PDU values
- chaining of index lookups even for indexes not being defined for the processed metric/table.
- identity lookups (i.e. where the lookup name is the same as the source\_index name) do not pull in the related index table from the SNMP target anymore (instead it gets generated on the-fly).
- sub OID filter for regex\_extracts, lookups and label regexes.
- new value type `uptime`: instructs snmp-exporter to convert the value (uptime TimeTicks) to a UNIX timestamp (boot time) -> constant values.
- automatic removal of leading and trailing whitespaces from PDU values
- production of always valid UTF-8 strings for DisplayString typed objects
- auto-indexing to handle objects with buggy MIB definitions
- ability to force bulkwalks
- definition of the labelname for automatically inserted labels for non-numeric metric values on module as well as metric scope.
- enhanced DateAndTime handling.
- negate the outcome of a match, i.e. replace only if regex does not match.
- better support for troubleshooting and optimization by OID "annotations"
- CLI output file option.

It follows the main motto: Tackle the root cause of inefficiency (e.g. do not compose/emit data no one needs) instead of the symptoms (e.g. with prometheus client relabeling) and thus saving a lot of ressources and finally energy.

To get an impression how far more or less interested people can get, have a look at the [snmp-export-cfg file](generator/generator.cisco.yml) we use to produce our production exporter configuration file (snippet) wrt. our Cisco equipment. The related directory contains other more or less useful examples: just check the `generator.*.yml` files.


# HowTo Build
```
make
```

# HowTo Install
```
make install
```
There are also binary packages for Ubuntu 20.04 via https://pkg.cs.ovgu.de/LNF/linux/ubuntu/20.04/ as well as for Solaris 11 via https://pkg.cs.ovgu.de/LNF/i386/5.11/ and http://pkg.cs.ovgu.de/lnf/en/catalog.shtml, which provide snmp-export as a system service via systemd and rstartd respectively.


# HowTo use example
```
export MIBDIRS=mibs		# a ':' separated list of dirs containing required MIBs
snmp-export-cfg generate -f generator/generator.cisco.yml -o /tmp/snmp-export.yml

# scp /tmp/snmp-export.yml somwhere_else:/tmp/ && ssh somwhere_else
snmp-export -f /tmp/snmp-export.yml

# In another terminal, e.g. to query everything defined in the module 'test':
curl -s 'http://localhost:9116/snmp?compact&module=test&target=YourVictim'
```

For more options see `snmp-export-cfg -h` and `snmp-export -h`.
