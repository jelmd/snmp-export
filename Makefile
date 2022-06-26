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
#
# Copyright 2022 Jens Elkner

SHELL := $(shell [ -x /bin/ksh93 ] && echo '/bin/ksh93' || echo '/bin/bash' )

VERSION := 2.0.0
PATCH ?= patch

# If you have your libnetsnmp.so in a non-standard directory, you may set the
# search path list here (a ':' separated list of lib dirs to use for lookup).
#LD_LIBRARY_PATH_GO ?= /home/admin/s11/lib

# If you do not want to have a RUNPATH set relative to the binary, set this
# env variable to 'true'.
ELFEDIT ?= $(firstword $(shell which patchelf))
ifeq ($(ELFEDIT),no)
	# on illumos the GNU elfedit crap comes first in the default path
	# but we need the original Solaris heritage.
	ELFEDIT = $(firstword $(shell PATH=/usr/bin:$PATH which elfedit))
endif
ifeq ($(ELFEDIT),no)
	ELFEDIT := true
endif


GO ?= go
GO_FMT ?= gofmt
GO_BIN_PATH := $(firstword $(subst :, ,$(shell $(GO) env GOPATH)/bin))
GO_LINT ?= $(firstword $(shell PATH=$(PATH):$(GO_BIN_PATH) which golangci-lint))
GO_OS ?= $(shell $(GO) env GOOS)
GO_ARCH ?= $(shell $(GO) env GOARCH)

DOLLAR := '$$'

CGO ?= 1
GO_FLAGS := -trimpath -mod=vendor
GO_LDFLAGS := -X 'main.Version=$(VERSION)' -extldflags '-zignore' -extldflags '-zdefs'

ifneq ($(LD_LIBRARY_PATH_GO),)
	GO_LDFLAGS += -extldflags '-Wl,-R,$(LD_LIBRARY_PATH_GO)'
    ifeq ($(ELFEDIT),)
		ELFEDIT = true
	endif
else
	LD_LIBRARY_PATH_GO = .
	ELFEDIT = true
endif
ifneq ($(INCLUDE_PATH_GO),)
	GO_CFLAGS += -gcflags "-I $(INCLUDE_PATH_GO)"
endif
INSTALL_PREFIX ?= /usr
BINDIR ?= $(INSTALL_PREFIX)/bin
SBINDIR ?= $(INSTALL_PREFIX)/sbin


# GNU install is needed for 'make install'
INSTALL_solaris = ginstall
INSTALL_linux = install
INSTALL ?= $(INSTALL_$(GO_OS))
ifeq ($(INSTALL),)
	INSTALL := install
endif

BASEDIR = $(PWD)
WORKDIR = $(BASEDIR)
HELP_PATCH_FILE := vendor/github.com/prometheus/common/expfmt/text_create.go

RACE_SUPPORT := linux/amd64 freebsd/amd64 darwin/amd64 windows/amd64 \
				linux/ppc64le linux/arm64

ifneq ($(RACE_SUPPORT),$(subst $(GO_OS)/$(GO_ARCH)," ",$(RACE_SUPPORT)))
	ifeq ($(CGO),1)
		RACE := -race
	endif
endif

progs: snmp-export snmp-export-cfg

clean-mibs:
	rm -rf $(MIBDIR) generator/mibs

clean: clean-mibs
	rm -rf bin snmp-export generator/generator

realclean: clean
	go clean
	rm -rf vendor

update-vendor:
	GO111MODULE=on $(GO) get -u -d ./generator/...
	GO111MODULE=on $(GO) mod tidy
	GO111MODULE=on $(GO) mod vendor
	[[ $(HELP_PATCH_FILE) -nt $(HELP_PATCH_FILE).orig ]] && \
		$(PATCH) -z.orig -b -p1 -i compact_vendor.patch

vendor:
	[[ -d vendor ]] || $(MAKE) update-vendor

snmp-export: BINARY := $(BASEDIR)/bin/snmp-export
snmp-export: ELFEDIT = true		# no need for RUNPATH adjustment

snmp-export-pure: CGO := 0
snmp-export-pure: RACE :=
snmp-export-pure: BINARY := ./bin/snmp-export
snmp-export-pure: ELFEDIT = true

snmp-export-cfg: WORKDIR := $(BASEDIR)/generator
snmp-export-cfg-test: WORKDIR := $(BASEDIR)/generator
snmp-export-cfg: CGO := 1
snmp-export-cfg-test: CGO := 1
snmp-export-cfg: BINARY := $(BASEDIR)/bin/snmp-export-cfg

# NOTE: elfedit on linux is undocumented so we do not use it
snmp-export snmp-export-cfg snmp-export-pure: vendor $(WORKDIR)/*.go
	cd $(WORKDIR) && CGO_LDFLAGS='-L $(LD_LIBRARY_PATH_GO)' \
	CGO_ENABLED=$(CGO) GO111MODULE=on $(GO) build $(RACE) \
		$(GO_FLAGS) $(GO_CFLAGS) -ldflags "$(GO_LDFLAGS)" -o $(BINARY)
	@[[ $(ELFEDIT) =~ 'patchelf' ]] && $(ELFEDIT) --set-rpath '$$ORIGIN:$$ORIGIN/../lib/$(GO_ARCH)' $(BINARY) || \
		( [[ $(GO_OS) != 'linux' ]] && ADDR=`$(ELFEDIT) -e 'dyn:runpath -o num' $(BINARY)` && \
		$(ELFEDIT) -e "str:set -shnam .dynstr -strndx $$ADDR $(DOLLAR)ORIGIN:$(DOLLAR)ORIGIN/../lib/$(GO_ARCH)" $(BINARY) || true )


%-test: $(WORKDIR)/*.go
	@cd $(WORKDIR) && CGO_LDFLAGS='-L $(LD_LIBRARY_PATH_GO)' \
	CGO_ENABLED=$(CGO) GO111MODULE=on $(GO) test $(TESTFLAGS) $(RACE) \
		$(GO_FLAGS) $(GO_CFLAGS) -ldflags "$(GO_LDFLAGS)"

test: snmp-export-test snmp-export-cfg-test

test-short: TESTFLAGS += -short
test-short: test

.PHONY: install clean realclean

install: snmp-export snmp-export-cfg
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 $(BASEDIR)/bin/snmp-export $(DESTDIR)$(SBINDIR)/snmp-export
	$(INSTALL) -m 755 $(BASEDIR)/bin/snmp-export-cfg $(DESTDIR)$(BINDIR)/snmp-export-cfg



install-golint:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GO_BIN_PATH)

golint:
	@[[ -z "$(GO_LINT)" || "$(GO_LINT)" == 'no' ]] && echo "Please install golangci-lint (e.g. using 'make install-golint') and try again." || $(GO_LINT) run --timeout 2m

fmt:
	GO111MODULE=on $(GO_FMT) -l -d -s *.go generator/*.go

release: golint progs test
