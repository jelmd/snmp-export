// Copyright 2018 The Prometheus Authors
// Portions Copyright 2022 Jens Elkner (jel+snmp-exporter@cs.uni-magdeburg.de)
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"

	"github.com/jelmd/snmp-export/config"
)

// The generator config.
type Config struct {
	Modules map[string]*ModuleConfig `yaml:"modules"`
}

type MetricOverrides struct {
	Ignore         bool                              `yaml:"ignore,omitempty"`
	RegexpExtracts map[string][]config.RegexpExtract `yaml:"regex_extracts,omitempty"`
	Type           string                            `yaml:"type,omitempty"`
	Remap          map[string]string                 `yaml:"remap,omitempty"`
	Rename         []config.RegexpExtract            `yaml:"rename,omitempty"`
    FallbackLabel  string                     `yaml:"fallback_label,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *MetricOverrides) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain MetricOverrides
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	// Ensure type for override is valid if one is defined.
	typ, ok := metricType(c.Type)
	if c.Type != "" && (!ok || typ != c.Type) {
		return fmt.Errorf("invalid metric type override '%s'", c.Type)
	}

	return nil
}

type ModuleConfig struct {
	Walk       []string                   `yaml:"walk"`
	Lookups    []*Lookup                  `yaml:"lookups"`
	WalkParams config.WalkParams          `yaml:",inline"`
	Overrides  map[string]MetricOverrides `yaml:"overrides"`
	Prefix     string                     `yaml:"prefix,omitempty"`
}

type Lookup struct {
	SourceIndexes     []string `yaml:"source_indexes"`
	Lookup            string   `yaml:"lookup"`
	DropSourceIndexes bool     `yaml:"drop_source_indexes,omitempty"`
	Rename            string   `yaml:"rename,omitempty"`
	Revalue           config.RegexpExtract  `yaml:"revalue,omitempty"`
	Mprefix           []string `yaml:"mprefix,omitempty"`
	Remap             map[string]string `yaml:"remap,omitempty"`
	SubOidRemap       map[string]string `yaml:"sub_oid_remap,omitempty"`
	SubOids           config.Regexp     `yaml:"sub_oids,omitempty"`
}
