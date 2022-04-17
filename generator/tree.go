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
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/prometheus/snmp_exporter/config"
)

// These types have one following the other.
// We need to check indexes and sequences have them
// in the right order, so the exporter can handle them.
var combinedTypes = map[string]string{
	"InetAddress":            "InetAddressType",
	"InetAddressMissingSize": "InetAddressType",
	"LldpPortId":             "LldpPortIdSubtype",
}

// Helper to walk MIB nodes.
func walkNode(n *Node, f func(n *Node)) {
	f(n)
	for _, c := range n.Children {
		walkNode(c, f)
	}
}

// Transform the tree.
func prepareTree(nodes *Node, logger log.Logger) map[string]*Node {
	// Build a map from names and oids to nodes.
	nameToNode := map[string]*Node{}
	walkNode(nodes, func(n *Node) {
		nameToNode[n.Oid] = n
		nameToNode[n.Label] = n
	})

	// Trim down description to first sentence, removing extra whitespace.
	walkNode(nodes, func(n *Node) {
		s := strings.Join(strings.Fields(n.Description), " ")
		n.Description = strings.Split(s, ". ")[0]
	})

	// Fix indexes to "INTEGER" rather than an object name.
	// Example: snSlotsEntry in LANOPTICS-HUB-MIB.
	walkNode(nodes, func(n *Node) {
		indexes := []string{}
		for _, i := range n.Indexes {
			if i == "INTEGER" {
				// Use the TableEntry name.
				indexes = append(indexes, n.Label)
			} else {
				indexes = append(indexes, i)
			}
		}
		n.Indexes = indexes
	})

	// Copy over indexes based on augments.
	walkNode(nodes, func(n *Node) {
		if n.Augments == "" {
			return
		}
		augmented, ok := nameToNode[n.Augments]
		if !ok {
			level.Warn(logger).Log("msg", "Can't find augmenting node", "augments", n.Augments, "node", n.Label)
			return
		}
		for _, c := range n.Children {
			c.Indexes = augmented.Indexes
			c.ImpliedIndex = augmented.ImpliedIndex
		}
		n.Indexes = augmented.Indexes
		n.ImpliedIndex = augmented.ImpliedIndex
	})

	// Copy indexes from table entries down to the entries.
	walkNode(nodes, func(n *Node) {
		if len(n.Indexes) != 0 {
			for _, c := range n.Children {
				c.Indexes = n.Indexes
				c.ImpliedIndex = n.ImpliedIndex
			}
		}
	})

	// Include both ASCII and UTF-8 in DisplayString, even though DisplayString
	// is technically only ASCII.
	displayStringRe := regexp.MustCompile(`^\d+[at]$`)

	// Apply various tweaks to the types.
	walkNode(nodes, func(n *Node) {
		// Set type on MAC addresses and strings.
		// RFC 2579
		switch n.Hint {
		case "1x:":
			n.Type = "PhysAddress48"
		}
		if displayStringRe.MatchString(n.Hint) {
			n.Type = "DisplayString"
		}

		// Some MIBs refer to RFC1213 for this, which is too
		// old to have the right hint set.
		if n.TextualConvention == "DisplayString" {
			n.Type = "DisplayString"
		}
		if n.TextualConvention == "PhysAddress" {
			n.Type = "PhysAddress48"
		}

		// Promote Opaque Float/Double textual convention to type.
		if n.TextualConvention == "Float" || n.TextualConvention == "Double" {
			n.Type = n.TextualConvention
		}

		// Convert RFC 2579 DateAndTime textual convention to type.
		if n.TextualConvention == "DateAndTime" {
			n.Type = "DateAndTime"
		}
		// Convert RFC 4001 InetAddress types textual convention to type.
		if n.TextualConvention == "InetAddressIPv4" || n.TextualConvention == "InetAddressIPv6" || n.TextualConvention == "InetAddress" {
			n.Type = n.TextualConvention
		}
		// Convert LLDP-MIB LldpPortId type textual convention to type.
		if n.TextualConvention == "LldpPortId" {
			n.Type = n.TextualConvention
		}
	})

	return nameToNode
}

func metricType(t string) (string, bool) {
	if _, ok := combinedTypes[t]; ok {
		return t, true
	}
	switch t {
	case "gauge", "INTEGER", "GAUGE", "TIMETICKS", "UINTEGER", "UNSIGNED32", "INTEGER32":
		return "gauge", true
	case "counter", "COUNTER", "COUNTER64":
		return "counter", true
	case "OctetString", "OCTETSTR", "OBJID":
		return "OctetString", true
	case "BITSTRING":
		return "Bits", true
	case "InetAddressIPv4", "IpAddr", "IPADDR", "NETADDR":
		return "InetAddressIPv4", true
	case "PhysAddress48", "DisplayString", "Float", "Double", "InetAddressIPv6":
		return t, true
	case "DateAndTime":
		return t, true
	case "EnumAsInfo", "EnumAsStateSet":
		return t, true
	default:
		// Unsupported type.
		return "", false
	}
}

func metricAccess(a string) bool {
	switch a {
	case "ACCESS_READONLY", "ACCESS_READWRITE", "ACCESS_CREATE", "ACCESS_NOACCESS":
		return true
	default:
		// the others are inaccessible metrics.
		return false
	}
}

// Reduce a set of overlapping OID subtrees.
func minimizeOids(oids []string) []string {
	sort.Strings(oids)
	prevOid := ""
	minimized := []string{}
	for _, oid := range oids {
		if !strings.HasPrefix(oid+".", prevOid) || prevOid == "" {
			minimized = append(minimized, oid)
			prevOid = oid + "."
		}
	}
	return minimized
}

// Search node tree for the longest OID match.
func searchNodeTree(oid string, node *Node) *Node {
	if node == nil || !strings.HasPrefix(oid+".", node.Oid+".") {
		return nil
	}

	for _, child := range node.Children {
		match := searchNodeTree(oid, child)
		if match != nil {
			return match
		}
	}
	return node
}

type oidMetricType uint8

const (
	oidNotFound oidMetricType = iota
	oidScalar
	oidInstance
	oidSubtree
)

// Find node in SNMP MIB tree that represents the metric.
func getMetricNode(oid string, node *Node, nameToNode map[string]*Node) (*Node, oidMetricType) {
	// Check if is a known OID/name.
	n, ok := nameToNode[oid]
	if ok {
		// Known node, check if OID is a valid metric or a subtree.
		_, ok = metricType(n.Type)
		if ok && metricAccess(n.Access) && len(n.Indexes) == 0 {
			return n, oidScalar
		} else {
			return n, oidSubtree
		}
	}

	// Unknown OID/name, search Node tree for longest match.
	n = searchNodeTree(oid, node)
	if n == nil {
		return nil, oidNotFound
	}

	// Table instances must be a valid metric node and have an index.
	_, ok = metricType(n.Type)
	ok = ok && metricAccess(n.Access)
	if !ok || len(n.Indexes) == 0 {
		return nil, oidNotFound
	}
	return n, oidInstance
}

func generateConfigModule(mname string, cfg *ModuleConfig, node *Node, nameToNode map[string]*Node, logger log.Logger) (*config.Module, error) {
	out := &config.Module{}
	needToWalk := map[string]struct{}{}
	tableInstances := map[string][]string{}

	// Apply type overrides for the current module.
	for name, params := range cfg.Overrides {
		if params.Type == "" || name == "_dummy" {
			continue
		}
		// Find node to override.
		n, ok := nameToNode[name]
		if !ok {
			level.Warn(logger).Log("msg", "Could not find node to override type", "module", mname, "node", name)
			continue
		}
		// params.Type validated at generator configuration.
		n.Type = params.Type
	}

	// Remove redundant OIDs to be walked.
	toWalk := []string{}
	for _, oid := range cfg.Walk {
		// Resolve name to OID if possible.
		if oid == "_dummy" {
			continue
		}
		n, ok := nameToNode[oid]
		if ok {
			toWalk = append(toWalk, n.Oid)
		} else {
			toWalk = append(toWalk, oid)
		}
	}
	toWalk = minimizeOids(toWalk)

	// Find all top-level nodes.
	metricNodes := map[*Node]struct{}{}
	for _, oid := range toWalk {
		metricNode, oidType := getMetricNode(oid, node, nameToNode)
		switch oidType {
		case oidNotFound:
			return nil, fmt.Errorf("cannot find oid '%s' to walk (module: %s)", oid, mname)
		case oidSubtree:
			needToWalk[oid] = struct{}{}
		case oidInstance:
			// Add a trailing period to the OID to indicate a "Get" instead of a "Walk".
			needToWalk[oid+"."] = struct{}{}
			// Save instance index for lookup.
			index := strings.Replace(oid, metricNode.Oid, "", 1)
			tableInstances[metricNode.Oid] = append(tableInstances[metricNode.Oid], index)
		case oidScalar:
			// Scalar OIDs must be accessed using index 0.
			needToWalk[oid+".0."] = struct{}{}
		}
		metricNodes[metricNode] = struct{}{}
	}
	// Sort the metrics by OID to make the output deterministic.
	metrics := make([]*Node, 0, len(metricNodes))
	for key := range metricNodes {
		metrics = append(metrics, key)
	}
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Oid < metrics[j].Oid
	})

	cfg.Prefix = sanitizeLabelName(cfg.Prefix)

	// Find all the usable metrics.
	for _, metricNode := range metrics {
		walkNode(metricNode, func(n *Node) {
			t, ok := metricType(n.Type)
			if !ok {
				return // Unsupported type.
			}

			if !metricAccess(n.Access) {
				return // Inaccessible metrics.
			}

			if cfg.Overrides[n.Label].Ignore {
				return // Ignored metric.
			}

			metric := &config.Metric{
				Name:       sanitizeMetricName(n.Label, cfg.Prefix),
				Oid:        n.Oid,
				Type:       t,
				Help:       n.Description + " - " + n.Oid,
				Indexes:    []*config.Index{},
				Lookups:    []*config.Lookup{},
				EnumValues: n.EnumValues,
			}

			prevType := ""
			// "copy" Indexes from the MIB node into the metric node
			for count, i := range n.Indexes {
				index := &config.Index{Labelname: i, IsNative: true}
				indexNode, ok := nameToNode[i]
				if !ok {
					level.Warn(logger).Log("msg", "Could not find index for node", "module", mname, "node", n.Label, "index", i)
					return
				}
				index.Type, ok = metricType(indexNode.Type)
				if !ok {
					level.Warn(logger).Log("msg", "Can't handle index type on node", "module", mname, "node", n.Label, "index", i, "type", indexNode.Type)
					return
				}
				index.FixedSize = indexNode.FixedSize
				if n.ImpliedIndex && count+1 == len(n.Indexes) {
					index.Implied = true
				}
				index.EnumValues = indexNode.EnumValues
				index.Oid = indexNode.Oid

				// Convert (InetAddressType,InetAddress) to (InetAddress)
				if subtype, ok := combinedTypes[index.Type]; ok {
					if prevType == subtype {
						metric.Indexes = metric.Indexes[:len(metric.Indexes)-1]
					} else {
						level.Warn(logger).Log("msg", "Can't handle index type on node, missing preceding", "module", mname, "node", n.Label, "type", index.Type, "missing", subtype)
						return
					}
				}
				prevType = indexNode.TextualConvention
				metric.Indexes = append(metric.Indexes, index)
			}
			out.Metrics = append(out.Metrics, metric)
		})
	}


	// Apply lookups.

	// first normalize possible metric prefixes
	for _, lookup := range cfg.Lookups {
		for n, mname := range lookup.Mprefix {
			lookup.Mprefix[n] = sanitizeMetricName(strings.TrimSpace(mname), cfg.Prefix)
		}
	}

	// now apply to relevant metrics
	for _, metric := range out.Metrics {
		toDelete := []string{}
        s := ""
		lookupSeen := map[string]int{}
		for _, lookup := range cfg.Lookups {
			if len(lookup.Mprefix) > 0 {
				found := false
				for _, mname := range lookup.Mprefix {
					if strings.HasPrefix(metric.Name, mname) || strings.HasPrefix(metric.Oid, mname) {
						found = true
						break
					}
				}
				if ! found {
					continue
				}
			}
			foundIndexes := 0
			// See if all source indexes are defined for the target.
			// metric.Indexes are the indexes found in the MIB definition of
			// the related target aka table.
			for _, lookupIndex := range lookup.SourceIndexes {
				found := false
				for _, index := range metric.Indexes {
					if index.Labelname == lookupIndex {
						foundIndexes++
						found = true
						break
					}
				}
				if (! found) && (lookupIndex != "_dummy") {
					s += ", " + lookupIndex
				}
			}
			l := &config.Lookup{ Labelvalue: lookup.Revalue, Remap: lookup.Remap }
			l.Inject = len(lookup.SourceIndexes) == 0
			if (! l.Inject) && (foundIndexes != len(lookup.SourceIndexes) || foundIndexes == 0) {
				if len(s) > 0 {
					m := metric.Name
					if len(cfg.Prefix) > 0 {
						m = metric.Name[len(cfg.Prefix)+1:]
					}
					level.Debug(logger).Log("msg", "Skipping lookup", "module", mname, "metric", m, "not defined in MIB", s[2:])
				}
				continue
			}

			oid_name := strings.Split(lookup.Lookup, "|")
			last := len(oid_name) - 1
			if l.Inject {
				for  c, label := range oid_name {
					// add as pseudo index so that we get subOids as needed
					idxNode, ok := nameToNode[label]
					if !ok {
						return nil, fmt.Errorf("Could not find pseudo index '%s' for %s::%s", label, mname, metric.Name)
					}
					idx := &config.Index{Labelname: label}
					idx.Type, ok = metricType(idxNode.Type)
					if !ok {
						return nil, fmt.Errorf("No type info found for pseudo index '%s' for %s::%s", label, mname, metric.Name)
					}
					idx.Oid = idxNode.Oid
					idx.FixedSize = idxNode.FixedSize
					idx.Implied = idxNode.ImpliedIndex
					idx.EnumValues = idxNode.EnumValues
					metric.Indexes = append(metric.Indexes, idx)
					if (c < last) {
						if len(tableInstances[metric.Oid]) > 0 {
							for _, idx := range tableInstances[metric.Oid] {
								needToWalk[idxNode.Oid + idx + "."] = struct{}{}
							}
						} else {
							needToWalk[idxNode.Oid] = struct{}{}
						}
					}
				}
			}

			// applies to the final value of the lookup
			for _, oldIndex := range lookup.SourceIndexes {
				l.Labels = append(l.Labels, sanitizeLabelName(oldIndex))
			}

			// chain of index names to lookup with the value of the prev. index
			var indexNode *Node
			for  c, label := range oid_name {
				if label == "_dummy" {
					continue
				}
				var ok bool
				indexNode, ok = nameToNode[label]
				if !ok {
					return nil, fmt.Errorf("unknown index '%s' (module: %s)", lookup.Lookup, mname)
				}
				typ, ok := metricType(indexNode.Type)
				if !ok {
					return nil, fmt.Errorf("unknown index type %s for %s (module: %s)", indexNode.Type, label, mname)
				}
				l.Type = append(l.Type, typ)
				l.Oid = append(l.Oid, indexNode.Oid)
				if (c < last) {
					if ! l.Inject {
						if typ != "gauge" {
							// for indexed lookups we need numbers
							return nil, fmt.Errorf("Type of index %s in index chain '%s' is not 'gauge' (module: %s)", label, lookup.Lookup, mname)
						}
						needToWalk[indexNode.Oid] = struct{}{}
					}
					l.Labelname = append(l.Labelname, sanitizeLabelName(indexNode.Label))
				}
			}
			if indexNode != nil {
				// labelname, which should be finally used in the constructed
				// metric instead of the indexes labels
				l.Labelname = append(l.Labelname, renameLabel(indexNode.Label, lookup.Rename))

				// Make sure we walk the lookup OID(s) unless it is a native Idx
				// for identity Lookups
				pullIn := true
				for _, oldIndex := range lookup.SourceIndexes {
					if oldIndex == indexNode.Label {
						pullIn = false
						break
					}
				}
				if pullIn {
					if len(tableInstances[metric.Oid]) > 0 {
						for _, index := range tableInstances[metric.Oid] {
							needToWalk[indexNode.Oid+index+"."] = struct{}{}
						}
					} else {
						needToWalk[indexNode.Oid] = struct{}{}
					}
				}
			}
			h := getLookupHash(l);
			_, ok := lookupSeen[h]
			if ! ok {
				if len(l.Oid) != 0 {
					metric.Lookups = append(metric.Lookups, l)
				}
				lookupSeen[h] = 1
				if lookup.DropSourceIndexes {
					// the labels to drop from the final label map
					toDelete = append(toDelete, l.Labels...)
					toDelete = append(toDelete, l.Labelname[:last]...)
				}
			}
		}

		if len(toDelete) > 0 {
			m := &config.Lookup{}
			m.Labelname = append(m.Labelname , toDelete...)
			metric.Lookups = append(metric.Lookups, m)
		}
	}

	// Ensure index label names are sane.
	for _, metric := range out.Metrics {
		for _, index := range metric.Indexes {
			index.Labelname = sanitizeLabelName(index.Labelname)
		}
	}

	// Check that the object before an InetAddress is an InetAddressType,
	// if not, change it to an OctetString.
	for _, metric := range out.Metrics {
		if metric.Type == "InetAddress" || metric.Type == "InetAddressMissingSize" {
			// Get previous oid.
			oids := strings.Split(metric.Oid, ".")
			i, _ := strconv.Atoi(oids[len(oids)-1])
			oids[len(oids)-1] = strconv.Itoa(i - 1)
			prevOid := strings.Join(oids, ".")
			if prevObj, ok := nameToNode[prevOid]; !ok || prevObj.TextualConvention != "InetAddressType" {
				metric.Type = "OctetString"
			} else {
				// Make sure the InetAddressType is included.
				if len(tableInstances[metric.Oid]) > 0 {
					for _, index := range tableInstances[metric.Oid] {
						needToWalk[prevOid+index+"."] = struct{}{}
					}
				} else {
					needToWalk[prevOid] = struct{}{}
				}
			}
		}
	}

	// Apply module config overrides to their corresponding metrics.
	for mname, params := range cfg.Overrides {
		s := sanitizeMetricName(mname, cfg.Prefix)
		for suffix, regexpair := range params.RegexpExtracts {
			var t string
			if len(suffix) > 0 && suffix[0] == '.' {
				t = "." + sanitizeMetricName(suffix[1:], cfg.Prefix)
			} else {
				t = sanitizeLabelName(suffix)
			}
			if t != suffix {
				delete(params.RegexpExtracts, suffix)
				params.RegexpExtracts[t] = regexpair
			}
		}
		for _, metric := range out.Metrics {
			if s == metric.Name || s == sanitizeMetricName(metric.Oid, cfg.Prefix) {
				metric.RegexpExtracts = params.RegexpExtracts
				metric.Remap = params.Remap
			}
		}
	}

	oids := []string{}
	for k := range needToWalk {
		oids = append(oids, k)
	}
	// Remove redundant OIDs and separate Walk and Get OIDs.
	for _, k := range minimizeOids(oids) {
		if k[len(k)-1:] == "." {
			out.Get = append(out.Get, k[:len(k)-1])
		} else {
			out.Walk = append(out.Walk, k)
		}
	}
	return out, nil
}

// Basically used to "compare" and drop duplicated lookups
func getLookupHash(l *config.Lookup) string {
	s := strings.Join(l.Labels, ":") + strings.Join(l.Labelname, ":") +
		strings.Join(l.Oid, ":") + strings.Join(l.Type, ":");
	if len(l.Labelvalue.Value ) > 0 {
		s += ":" + l.Labelvalue.Value + ":"  + l.Labelvalue.Regex.String()
	}
	return s
}

var (
	invalidLabelCharRE = regexp.MustCompile(`[^a-zA-Z0-9_]`)
)

func sanitizeMetricName(name string, prefix string) string {
	s := strings.TrimSpace(prefix)
	if len(s) > 0 {
		s = invalidLabelCharRE.ReplaceAllString(s, "_")
		return s + "_" + strings.TrimPrefix(invalidLabelCharRE.ReplaceAllString(name, "_"), s)
	}
	return invalidLabelCharRE.ReplaceAllString(name, "_")
}
func renameLabel(name string, newName string) string {
	s := strings.TrimSpace(newName)
	if len(s) > 0 {
		return invalidLabelCharRE.ReplaceAllString(s, "_")
	}
	return invalidLabelCharRE.ReplaceAllString(name, "_")
}
func sanitizeLabelName(name string) string {
	return invalidLabelCharRE.ReplaceAllString(name, "_")
}
