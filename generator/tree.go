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

// Just to avoid endles loops if someone gets too creative wrt. brace expressions
const maxBraceExpansionRounds = 1000
const maxBraceNestingDepth = 1000

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
	case "uptime", "UPTIME", "UPTIME64":
		return "uptime", true
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


func expandOverrides(s string, logger log.Logger) []string {
	if len(s) < 1 {
		return []string{}
	}

	a := strings.Split(s, "¦")
	if strings.IndexByte(s, '{') == -1 {
		return a
	}

	res := []string{}
	for _, o := range a {
		if len(o) == 0 {
			continue
		}
		l, _ := expandBraces(o, 0, logger);
		res = append(res, l...)
	}
	return res
}

func expandList(prefix string, list []string, suffix string, brace bool, depth int, logger log.Logger) string {
	// e.g. ucb/   ex,edit   ,lib/{ex,how_ex} => ucb/ex,ucb/edit,lib/{ex,how_ex}
	if len(list) == 0 {
		return ""
	}
	var sb strings.Builder
	pprefix := ""
	iprefix := ","  + prefix
	isuffix := suffix
	psuffix := ""
	i := -1
	if depth > 0 {
		i = strings.LastIndexByte(prefix, ',')
	}
	if i != -1 {
		pprefix = prefix[:i+1]
		iprefix = prefix[i:]
	}
	// i = strings.IndexByte(suffix, ',') doesn't always work
	brace_count := 0
	i = -1
	if depth > 0 {
		for k := 0; k < len(suffix); k++ {
			if suffix[k] == ',' && brace_count == 0 {
				i = k
				break;
			}
			if suffix[k] == '{' && (k == 0 || suffix[k-1] != '\\') {
				brace_count++
			} else if suffix[k] == '}' && (k == 0 || suffix[k-1] != '\\') && brace_count != 0 {
				brace_count--
			}
		}
	}
	if i != -1 {
		isuffix = suffix[:i]
		psuffix = suffix[i:]
	}
	level.Debug(logger).Log("ListExpansion",
		prefix + "|" + strings.Join(list, "¦") + "|" + suffix,
		"pprefix", pprefix, "iprefix", iprefix, "isuffix", isuffix, "psuffix", psuffix, "brace", brace)

	for _,s := range list {
		for _,t := range strings.Split(s, ",") {
			sb.WriteString(iprefix)
			sb.WriteString(t)
			sb.WriteString(isuffix)
		}
	}
	t := ""
	if brace {
		t = pprefix + "{" + sb.String()[1:] + "}" + psuffix
	} else {
		t = pprefix + sb.String()[1:] + psuffix
	}
	level.Debug(logger).Log("ListExpansion_result", t)
	return t
}

func expandBraces(s string, depth int, logger log.Logger) ([]string, bool) {
	/*
	If l1,l2 are either all lower case or all upper case letters in C locale,
	n1,n2,n3 signed numbers, and
	fmt a string specified as in fmt.Printf we support the following
	brace expansions similar to ksh93:
		(1) `{s[,s1]...}`
		(2) `{l1..l2[..n3][%fmt]}`
		(3) `{n1..n2[..n3][%fmt]}`
	The curly braces, dots and percent sign are literals, the brackets mark an
	optional part of the brace expression - need to be ommitted.

	In the first form the function iterates over the comma separated list of
	strings and generates for each member a new string by replacing the brace
	expression with the member.
	E.g. `foo{bar,sel,l}` becomes `foobar|foosel|fool`.

	In the second and third form the generator iterates from l1 through l2
	or n1 through n2 using the given step width n3. If n3 is not given, it
	gets set to 1 or -1 depending on the first and second argument. If %fmt
	is given, it will be used to create the string from the generated character
	or number. Otherwise `%c` (2nd form) or `%d`(3rd form) will be used.

	Finally a new list of strings gets generated, where the brace expression
	gets replaced by the members of the one-letter list one-by-one.
	E.g. `chapter{A..F}.1` becomes
	`chapterA.1|chapterB.1|chapterC.1|chapterD.1|chapterE.1|chapterF.1`,
	and `{a,z}{1..5..3%02d}{b..c}x` expands to 2x2x2 == 8 strings:
    `a01bx|a01cx|a04bx|a04cx|z01bx|z01cx|z04bx|z04cx`.

	One may escape curly braces with a backslash(`\`), but since they are not
	allowed in metric names, it doesn't make much sense for the generator case.
	Any brace expression which cannot be parsed or uses invalid arguments gets
	handled as literal without the enclosing curly braces. Note that in the
	2nd form only ASCII letters in the range of `a-z` and `A-Z` are accepted,
	only.
	*/
	if len(s) == 0 {
		return []string{ s } , false
	}
	if depth >= maxBraceNestingDepth {
			level.Warn(logger).Log("msg", fmt.Sprintf("Brace expansion aborted because of too many nested brace expressions (%d). Check '%s' for brace insertion.", depth, s))
			return []string{ s } , false
	}

	level.Debug(logger).Log("Expand_Brace", s, "depth", depth)
	src := []string{ s }
	src_modified := []bool{ true }
	res := []string{}
	res_modified := []bool{}
	modified := true
	count := 0
	for modified {
		if count >= maxBraceExpansionRounds {
			level.Warn(logger).Log("msg", fmt.Sprintf("Brace expansion aborted: still not fully expanded after %d rounds. Check '%s' for brace insertion.", count, s))
			return []string{ s } , false
		}
		count++
		level.Debug(logger).Log("Depth", depth, "count", count,
			"src", strings.Join(src, ","))
		modified = false
		for i, t := range src {
			if ! src_modified[i] {
				// since we need to keep the order this is much simpler instead
				// of taking them out from src and do add. book keeping
				res = append(res, t)
				res_modified = append(res_modified, false)
				continue
			}
			b := -1
			e := -1
			for k:= 0 ; k < len(t); k++ {
				if t[k] == '{' && (k == 0 || t[k-1] != '\\') {
					b = k
					break
				}
			}
			if b != -1 {
				open := 0
				// find the closing brace
				for k:= b+1 ; k < len(t); k++ {
					if t[k] == '}' && t[k-1] != '\\' {
						if open == 0 {
							e = k
							break
						}
						open--
					} else if t[k] == '{' && t[k-1] != '\\' {
						open++
					}
				}
			}
			if (b != -1 || e != -1) && (b == -1 || e == -1 || b > e) {
				res = append(res, t)		// unbalanced
				res_modified = append(res_modified, false)
				continue
			}
			if b == -1 {
				res = append(res, t)		// no braces
				res_modified = append(res_modified, false)
				continue
			}
			prefix := t[:b]
			suffix := t[e+1:]
			expr := t[b+1:e]
			level.Debug(logger).Log("Prefix",prefix,"Suffix",suffix,"Expr",expr)
			l, mod := expandBraces(expr, depth + 1, logger)
			if mod {
				if (depth > 0) {
					t = expandList(prefix, l, suffix, true, depth, logger)
					res = append(res, t)
				} else {
					t = strings.Join(l, ",")
					res = append(res, prefix + "{" + t + "}" + suffix)
				}
				level.Debug(logger).Log("Re-insert", t,
					"depth", depth, "count", count,)
				res_modified = append(res_modified, true)
				modified = true
				continue
			}
			// not modified, so expand ranges
			//idx := strings.LastIndexByte(prefix, ',')
			t, mod := expandRange(expr, logger)
			if mod {
				modified = true
				res = append(res, prefix + "{" + t + "}" + suffix)
				res_modified = append(res_modified, true)
				continue
			}
			// range not modified, so expand commas
			level.Debug(logger).Log("Splitting", expr)
			mod = false
			xl :=  strings.Split(expr, ",")
			if len(xl) > 1 {
				modified = true
				mod = true
			}
			t = expandList(prefix, xl, suffix, false, depth, logger)
			if depth > 0 {
				res = append(res, t)
				res_modified = append(res_modified, mod)
			} else {
				for _, t := range xl {
					res = append(res, prefix + t + suffix)
					res_modified = append(res_modified, mod)
				}
			}
		}

		if modified {
			src = res
			res = []string{}
			src_modified = res_modified
			res_modified = []bool{}
		} else {
			level.Debug(logger).Log("Done_round",count,
				"res", strings.Join(res, "¦"))
		}
	}
	level.Debug(logger).Log("depth",depth, "Returning", strings.Join(res, "¦"))
	return res , count > 1
}

func expandRange(expr string, logger log.Logger) (string, bool) {
	if len(expr) < 4 {
		return expr , false
	}
	level.Debug(logger).Log("Expanding_range", expr)
	idx := strings.Index(expr, "..")
	if idx == -1 {
		return expr , false
	}

	var sb strings.Builder
	start := expr[:idx]
	stop := expr[idx+2:]
	step := ""
	var sw int64 = 0
	fmtspec := ""

	// n3
	idx = strings.Index(stop, "..")
	if idx != -1 {
		step = stop[idx+2:]
		stop = stop[:idx]
	}

	// %fmt
	if len(step) == 0 {
		fidx := strings.IndexByte(stop, '%')
		if fidx != -1 {
			fmtspec = stop[fidx:]
			stop = stop[:fidx]
		}
	} else {
		fidx := strings.IndexByte(step, '%')
		if fidx != -1 {
			fmtspec = step[fidx:]
			step = step[:fidx]
		}
	}
	if len(step) != 0 {
		swo, err := strconv.ParseInt(step, 0, 64)
		if err != nil || swo == 0 {
			return expr , false
		}
		sw = swo
	}
	level.Debug(logger).Log("Range_params", ":",
		"start",start, "stop",stop, "step", step, "fmt", fmtspec)
	if  len(start) == 1 && len(stop) == 1 &&
		(start[0] < '0' || start[0] > '9' || stop[0] < '0' || stop[0] > '9') {
		level.Debug(logger).Log("RangeType", "l1..l2")
		// l1..l2
		b := start[0]
		e := stop[0]
		reverse := false
		if b > e {
			reverse = true
			c := b
			b = e
			e = c
		}
		if e >= 'a' {
			if b < 'a' || e > 'z' {
				return expr , false
			}
		} else if e >= 'A' {
			if b < 'A' || e > 'Z' {
				return expr , false
			}
		} else {
			return expr , false
		}
		if reverse {
			c := b
			b = e
			e = c
		}
		if (sw == 0) {
			sw = 1
			if b > e {
				sw = -1
			}
		}
		if (b > e) && (sw > 0) {
			// invalid step width
			return expr , false
		}
		var w byte = byte(sw)
		if len(fmtspec) == 0 {
			fmtspec = "%c"
		} else {
			t := fmt.Sprintf(fmtspec, b)
			if strings.HasPrefix(t, "%!") {
				return expr , false		// invalid format specifier
			}
		}
		level.Debug(logger).Log("Range_params", ":",
			"start",b, "stop",e, "step",w, "fmt", fmtspec)
		if b <= e {
			for i := b; i <= e; i += w {
				sb.WriteString(",")
				sb.WriteString(fmt.Sprintf(fmtspec, i))
			}
		} else {
			for i := b; i >= e; i += w {
				sb.WriteString(",")
				sb.WriteString(fmt.Sprintf(fmtspec, i))
			}
		}
		level.Debug(logger).Log("Range_Result", sb.String()[1:])
		return sb.String()[1:] , true
	}

	level.Debug(logger).Log("RangeType", "n1..n2")
	b, err := strconv.ParseInt(start, 0, 64)
	if err != nil {
		return  expr , false
	}
	e, err := strconv.ParseInt(stop, 0, 64)
	if err != nil {
		return  expr , false
	}
	if len(fmtspec) == 0 {
		fmtspec = "%d"
	} else {
		t := fmt.Sprintf(fmtspec, b)
		if strings.HasPrefix(t, "%!") {
			return expr , false		// invalid format specifier
		}
	}
	if sw == 0 {
		sw = 1
		if b > e {
			sw = -1
		}
	} else if (b > e && sw > 0) || (b < e && sw < 0) {
		return fmt.Sprintf(fmtspec, b), true
	}
	if b <= e {
		for i := b; i <= e; i += sw {
			sb.WriteString(",")
			sb.WriteString(fmt.Sprintf(fmtspec, i))
		}
	} else {
		for i := b; i >= e; i += sw {
			sb.WriteString(",")
			sb.WriteString(fmt.Sprintf(fmtspec, i))
		}
	}

	level.Debug(logger).Log("Range_Result", sb.String()[1:])
	return sb.String()[1:], true
}

func generateConfigModule(mname string, cfg *ModuleConfig, node *Node, nameToNode map[string]*Node, logger log.Logger) (*config.Module, error) {
	out := &config.Module{}
	needToWalk := map[string]struct{}{}
	tableInstances := map[string][]string{}
	ignore := map[string]bool{}
	relink := map[string]string{}

	// Apply type overrides for the current module.
	for key, params := range cfg.Overrides {
		level.Debug(logger).Log("module", mname, "Override", key, "TypeToForce", params.Type)
		mnames := expandOverrides(key, logger)
		if len(mnames) > 1 {
			// expand once, only.
			t := strings.Join(mnames, "¦")
			level.Debug(logger).Log("module", mname, "OverrideResult", t)
			if key != t {
				relink[key] = t
			}
		}
		for _, name := range mnames {
			if name == "_dummy" {
				continue
			}
			ignore[name] = params.Ignore
			if params.Type == "" {
				continue
			}
			// Find node to override.
			n, ok := nameToNode[name]
			if !ok {
				level.Warn(logger).Log("msg", "SNMP variable not found -> ignored", "module", mname, "name", name)
				continue
			}
			// params.Type validated on unmarshall
			level.Debug(logger).Log("module", mname, "metric", name, "metricType", n.Type, "forcedTo", params.Type)
			n.Type = params.Type
		}
	}
	for key, val := range relink {
		cfg.Overrides[val] = cfg.Overrides[key]
		delete(cfg.Overrides, key)
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

			if ignore[n.Label] {
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

	// first normalize possible metric prefixes and compile regex if needed
	mprefix_re := map[string]*regexp.Regexp{}
	for _, lookup := range cfg.Lookups {
		newList := []string{}
		for n, name := range lookup.Mprefix {
			if name[0] == '_' {
				// regex variant
				if len(cfg.Prefix) != 0 {
					lookup.Mprefix[n] = "_" + cfg.Prefix + name
				}
				x, err := regexp.Compile("^(?:" + lookup.Mprefix[n][1:] + ")")
				if err != nil {
					return nil, fmt.Errorf("invalid mprefix regex '%s' (module: %s)", name, mname)
				}
				mprefix_re[lookup.Mprefix[n]] = x
				newList = append(newList, lookup.Mprefix[n])
			} else {
				l := expandOverrides(strings.TrimSpace(name), logger)
				if len(l) > 1 {
					level.Debug(logger).Log("mprefix", name, "expanded", strings.Join(l, "¦"))
				}
				for _, prefix := range l {
					newList = append(newList, sanitizeMetricName(strings.TrimSpace(prefix), cfg.Prefix))
				}
			}
		}
		lookup.Mprefix = newList
	}

	// now apply to relevant metrics
	for _, metric := range out.Metrics {
		toDelete := map[string]int{}
        s := ""
		for _, lookup := range cfg.Lookups {
			if lookup.DropSourceIndexes {
				for _, idx := range metric.Indexes {
					toDelete[sanitizeLabelName(idx.Labelname)] = 1
				}
				break
			}
		}
		lookupSeen := map[string]int{}
		_idxSeen := false
		for _, lookup := range cfg.Lookups {
			mprefix_idxs := [][]int{}
			mprefix_used := ""
			if len(lookup.Mprefix) > 0 {
				found := false
				for _, mname := range lookup.Mprefix {
					if mname[0] == '_' {
						// need the official name here
						n, _ := nameToNode[metric.Oid]
						mprefix_idxs = mprefix_re[mname].FindAllStringSubmatchIndex(n.Label, -1)
						level.Debug(logger).Log("mprefix", mname, "metric", n.Label, "matched", len(mprefix_idxs) != 0)
						if len(mprefix_idxs) == 0 {
							continue
						}
						// match: TBD: keep indexes
						mprefix_used = mname
						found = true
						break
					} else if strings.HasPrefix(metric.Name, mname) || strings.HasPrefix(metric.Oid, mname) {
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
			l := &config.Lookup {
				Labelvalue: lookup.Revalue,
				Remap: lookup.Remap,
				SubOidRemap: lookup.SubOidRemap,
				SubOids: lookup.SubOids,
			}
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

			oid_name := strings.Split(lookup.Lookup, "¦")
			last := len(oid_name) - 1
			if l.Inject {
nextLabel:
				for  c, label := range oid_name {
					// add as pseudo index so that we get subOids as needed
					orig_label := ""
					if len(mprefix_idxs) > 0 && strings.IndexByte(label, '$') != -1 {
						b := []byte{}
						for _, submatches := range mprefix_idxs {
							b = mprefix_re[mprefix_used].ExpandString(b, label, metric.Name, submatches)
						}
						if len(b) != 0 {
							orig_label = label
							label = string(b)
						}
					}
					var idx *config.Index
					var idxNode *Node
					if label == "_idx" {
						if _idxSeen {
							continue nextLabel
						}
						idx = &config.Index{Labelname: label, Type: "DisplayString", Oid: "0", IsNative: false, }
						_idxSeen = true
					} else {
						ok := false
						idxNode, ok = nameToNode[label]
						if !ok {
							if len(orig_label) != 0 {
								return nil, fmt.Errorf("Could not find generated pseudo index '%s' for %s::%s (orig: %s)", label, mname, metric.Name, orig_label)
							} else {
								return nil, fmt.Errorf("Could not find pseudo index '%s' for %s::%s", label, mname, metric.Name)
							}
						}
						for _, midx := range metric.Indexes {
							if midx.Oid == idxNode.Oid {
								continue nextLabel
							}
						}
						idx = &config.Index{Labelname: label}
						idx.Type, ok = metricType(idxNode.Type)
						if !ok {
							return nil, fmt.Errorf("No type info found for pseudo index '%s' for %s::%s", label, mname, metric.Name)
						}
						idx.Oid = idxNode.Oid
						idx.FixedSize = idxNode.FixedSize
						idx.Implied = idxNode.ImpliedIndex
						idx.EnumValues = idxNode.EnumValues
					}
					metric.Indexes = append(metric.Indexes, idx)
					if c < last && label != "_idx" {
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
				if label == "_idx" {
					l.Type = append(l.Type, "DisplayText")
					l.Oid = append(l.Oid, "0")
				    l.Labelname = append(l.Labelname, renameLabel("_idx", lookup.Rename))
					continue
				}
				orig_label := ""
				if len(mprefix_idxs) > 0 && strings.IndexByte(label, '$') != -1 {
					b := []byte{}
					for _, submatches := range mprefix_idxs {
						b = mprefix_re[mprefix_used].ExpandString(b, label, metric.Name, submatches)
					}
					if len(b) != 0 {
						orig_label = label
						label = string(b)
					}
				}
				var ok bool
				indexNode, ok = nameToNode[label]
				if !ok {
					if len(orig_label) != 0 {
						return nil, fmt.Errorf("Could not find index '%s' for %s::%s (orig: %s)", label, mname, metric.Name, orig_label)
					} else {
						return nil, fmt.Errorf("Could not find index '%s' for %s::%s", label, mname, metric.Name)
					}
				}
				typ, ok := metricType(indexNode.Type)
				if !ok {
					return nil, fmt.Errorf("unknown index type %s for %s::%s", indexNode.Type, mname, label)
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
					for _, s := range l.Labels {
						toDelete[s] = 1
					}
					for _, s := range l.Labelname[:last] {
						toDelete[s] = 1
					}
				}
			}
		}

		if len(toDelete) > 0 {
			m := &config.Lookup{}
			for s, _ := range toDelete {
				m.Labelname = append(m.Labelname , s)
			}
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
	for key, params := range cfg.Overrides {
		for suffix, regexpair := range params.RegexpExtracts {
			var t string
			if len(suffix) > 0 && (suffix[0] == '.' || suffix[0] == '^') {
				if (suffix[0] == '.') {
					t = "." + sanitizeMetricName(suffix[1:], cfg.Prefix)
				} else {
					t = "." + sanitizeMetricName(suffix[1:], "")
				}
			} else {
				t = sanitizeLabelName(suffix)
			}
			if t != suffix {
				delete(params.RegexpExtracts, suffix)
				params.RegexpExtracts[t] = regexpair
			}
		}
		mnames := strings.Split(key, "¦")
		for _, name := range mnames {
			s := sanitizeMetricName(name, cfg.Prefix)
			for _, metric := range out.Metrics {
				if s == metric.Name || s == sanitizeMetricName(metric.Oid, cfg.Prefix) {
					metric.RegexpExtracts = params.RegexpExtracts
					metric.Remap = params.Remap
					metric.Rename = params.Rename
				}
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
		strings.Join(l.Oid, ":") + strings.Join(l.Type, ":") + ":"
	if len(l.Labelvalue.Value) != 0 {
		s += l.Labelvalue.Value + ":"  + l.Labelvalue.Regex.String() + ":"
		if l.Labelvalue.Invert {
			s += "true"
		} else {
			s += "false"
		}
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
