# Copyright 2016 The Prometheus Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Needs to be defined before including Makefile.common to auto-generate targets
DOCKER_ARCHS ?= amd64 armv7 arm64 ppc64le

INSTALL_PREFIX ?= /usr
BINDIR ?= $(INSTALL_PREFIX)/bin
SBINDIR ?= $(INSTALL_PREFIX)/sbin

# GNU install is needed for 'make install'
OS := $(shell uname -s)
INSTALL_SunOS = ginstall
INSTALL_Linux = install
INSTALL ?= $(INSTALL_$(OS))

include Makefile.common

STATICCHECK_IGNORE =

DOCKER_IMAGE_NAME ?= snmp-exporter

ifdef DEBUG
	bindata_flags = -debug
endif

generator/generator:
	$(MAKE) -C generator generator

snmp_exporter:
	$(MAKE) build

.PHONY: install
install: generator/generator snmp_exporter
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 snmp_exporter $(DESTDIR)$(SBINDIR)/snmp-export
	$(INSTALL) -m 755 generator/generator $(DESTDIR)$(BINDIR)/snmp-export-cfg
