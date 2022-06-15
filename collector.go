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
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/prometheus/snmp_exporter/config"
)

var (
	snmpUnexpectedPduType = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_unexpected_pdu_type_total",
			Help: "Unexpected Go types in a PDU.",
		},
	)
	// 64-bit float mantissa: https://en.wikipedia.org/wiki/Double-precision_floating-point_format
	float64Mantissa uint64 = 9007199254740992
	wrapCounters           = kingpin.Flag("snmp.wrap-large-counters", "Wrap 64-bit counters to avoid floating point rounding.").Default("true").Bool()
	nullRegexp config.Regexp		// for the golang null bullshit bingo
)

func init() {
	prometheus.MustRegister(snmpUnexpectedPduType)
}

// Types preceded by an enum with their actual type.
var combinedTypeMapping = map[string]map[int]string{
	"InetAddress": {
		1: "InetAddressIPv4",
		2: "InetAddressIPv6",
	},
	"InetAddressMissingSize": {
		1: "InetAddressIPv4",
		2: "InetAddressIPv6",
	},
	"LldpPortId": {
		1: "DisplayString",
		2: "DisplayString",
		3: "PhysAddress48",
		5: "DisplayString",
		7: "DisplayString",
	},
}

func oidToList(oid string) []int {
	result := []int{}
	for _, x := range strings.Split(oid, ".") {
		o, _ := strconv.Atoi(x)
		result = append(result, o)
	}
	return result
}

func listToOid(l []int) string {
	var result []string
	for _, o := range l {
		result = append(result, strconv.Itoa(o))
	}
	return strings.Join(result, ".")
}

func ScrapeTarget(ctx context.Context, target string, config *config.Module, logger log.Logger) ([]gosnmp.SnmpPDU, error) {
	// Set the options.
	snmp := gosnmp.GoSNMP{}
	snmp.Context = ctx
	snmp.MaxRepetitions = config.WalkParams.MaxRepetitions
	snmp.Retries = config.WalkParams.Retries
	snmp.Timeout = config.WalkParams.Timeout

	snmp.Target = target
	snmp.Port = 161
	if host, port, err := net.SplitHostPort(target); err == nil {
		snmp.Target = host
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("error converting port number to int for target %s: %s", target, err)
		}
		snmp.Port = uint16(p)
	}

	// Configure auth.
	config.WalkParams.ConfigureSNMP(&snmp)

	// Do the actual walk.
	err := snmp.Connect()
	if err != nil {
		if err == context.Canceled {
			return nil, fmt.Errorf("scrape canceled (possible timeout) connecting to target %s", snmp.Target)
		}
		return nil, fmt.Errorf("error connecting to target %s: %s", target, err)
	}
	defer snmp.Conn.Close()

	result := []gosnmp.SnmpPDU{}
	getOids := config.Get
	maxOids := int(config.WalkParams.MaxRepetitions)
	// Max Repetition can be 0, maxOids cannot. SNMPv1 can only report one OID error per call.
	if maxOids == 0 || snmp.Version == gosnmp.Version1 {
		maxOids = 1
	}
	for len(getOids) > 0 {
		oids := len(getOids)
		if oids > maxOids {
			oids = maxOids
		}

	if DebugEnabled {
		level.Debug(logger).Log("msg", "Getting OIDs", "oids", oids)
	}
		getStart := time.Now()
		packet, err := snmp.Get(getOids[:oids])
		if err != nil {
			if err == context.Canceled {
				return nil, fmt.Errorf("scrape canceled (possible timeout) getting target %s", snmp.Target)
			}
			return nil, fmt.Errorf("error getting target %s: %s", snmp.Target, err)
		}
	if DebugEnabled {
		level.Debug(logger).Log("msg", "Get of OIDs completed", "oids", oids, "duration_seconds", time.Since(getStart))
	}
		// SNMPv1 will return packet error for unsupported OIDs.
		if packet.Error == gosnmp.NoSuchName && snmp.Version == gosnmp.Version1 {
	if DebugEnabled {
			level.Debug(logger).Log("msg", "OID not supported by target", "oids", getOids[0])
	}
			getOids = getOids[oids:]
			continue
		}
		// Response received with errors.
		// TODO: "stringify" gosnmp errors instead of showing error code.
		if packet.Error != gosnmp.NoError {
			return nil, fmt.Errorf("error reported by target %s: Error Status %d", snmp.Target, packet.Error)
		}
		for _, v := range packet.Variables {
			if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance {
	if DebugEnabled {
				level.Debug(logger).Log("msg", "OID not supported by target", "oids", v.Name)
	}
				continue
			}
			result = append(result, v)
		}
		getOids = getOids[oids:]
	}

	for _, subtree := range config.Walk {
		var pdus []gosnmp.SnmpPDU
	if DebugEnabled {
		level.Debug(logger).Log("msg", "Walking subtree", "oid", subtree)
	}
		walkStart := time.Now()
		if snmp.Version == gosnmp.Version1 {
			pdus, err = snmp.WalkAll(subtree)
		} else {
			pdus, err = snmp.BulkWalkAll(subtree)
		}
		if err != nil {
			if err == context.Canceled {
				return nil, fmt.Errorf("scrape canceled (possible timeout) walking target %s", snmp.Target)
			}
			return nil, fmt.Errorf("error walking target %s: %s", snmp.Target, err)
		}
	if DebugEnabled {
		level.Debug(logger).Log("msg", "Walk of subtree completed", "oid", subtree, "duration_seconds", time.Since(walkStart))
	}

		result = append(result, pdus...)
	}
	return result, nil
}

type MetricNode struct {
	metric *config.Metric

	children map[int]*MetricNode
}

// Build a tree of metrics from the config, for fast lookup when there's lots of them.
func buildMetricTree(metrics []*config.Metric) *MetricNode {
	metricTree := &MetricNode{children: map[int]*MetricNode{}}
	for _, metric := range metrics {
		head := metricTree
		for _, o := range oidToList(metric.Oid) {
			_, ok := head.children[o]
			if !ok {
				head.children[o] = &MetricNode{children: map[int]*MetricNode{}}
			}
			head = head.children[o]
		}
		head.metric = metric
	}
	return metricTree
}

type collector struct {
	ctx    context.Context
	target string
	module *config.Module
	logger log.Logger
	compact bool
	name   string
}

// Describe implements Prometheus.Collector.
func (c collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("dummy", "dummy", nil, nil)
}

// Collect implements Prometheus.Collector.
func (c collector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	pdus, err := ScrapeTarget(c.ctx, c.target, c.module, c.logger)
	if err != nil {
		level.Info(c.logger).Log("msg", "Error scraping target", "err", err)
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "Error scraping target", nil, nil), err)
		return
	}
	help := ""
	if ! c.compact {
		help = "Time SNMP walk/bulkwalk took."
	}
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_walk_duration_seconds", help, nil, nil),
		prometheus.GaugeValue,
		time.Since(start).Seconds())
	if ! c.compact {
		help = "PDUs returned from walk."
	}
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_pdus_returned", help, nil, nil),
		prometheus.GaugeValue,
		float64(len(pdus)))
	oidToPdu := make(map[string]gosnmp.SnmpPDU, len(pdus))
	for _, pdu := range pdus {
		oidToPdu[pdu.Name[1:]] = pdu
	}

	idxCache := map[string]string{}
	metricTree := buildMetricTree(c.module.Metrics)
	// Look for metrics that match each pdu.
PduLoop:
	for oid, pdu := range oidToPdu {
		head := metricTree
		oidList := oidToList(oid)
		for i, o := range oidList {
			var ok bool
			head, ok = head.children[o]
			if !ok {
				continue PduLoop
			}
			if head.metric != nil {
				// Found a match.
				samples := pduToSamples(oidList[i+1:], &pdu, head.metric, oidToPdu, idxCache, c.logger, c.compact)
				for _, sample := range samples {
					ch <- sample
				}
				break
			}
		}
	}
	if ! c.compact {
		help = "Total SNMP time scrape took (walk and processing)."
	}
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_duration_seconds", help, nil, nil),
		prometheus.GaugeValue,
		time.Since(start).Seconds())
}

func getPduValue(pdu *gosnmp.SnmpPDU) float64 {
	switch pdu.Type {
	case gosnmp.Counter64:
		if *wrapCounters {
			// Wrap by 2^53.
			return float64(gosnmp.ToBigInt(pdu.Value).Uint64() % float64Mantissa)
		} else {
			return float64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	case gosnmp.OpaqueFloat:
		return float64(pdu.Value.(float32))
	case gosnmp.OpaqueDouble:
		return pdu.Value.(float64)
	default:
		return float64(gosnmp.ToBigInt(pdu.Value).Int64())
	}
}

var	timeZone, timeLocalDelta = time.Now().Zone()

// parseDateAndTime extracts a UNIX timestamp from an RFC 2579 DateAndTime.
func parseDateAndTime(pdu *gosnmp.SnmpPDU) (float64, error) {
	var (
		v   []byte
		tz  *time.Location
		err error
	)
	// DateAndTime should be a slice of bytes.
	switch pduType := pdu.Value.(type) {
	case []byte:
		v = pdu.Value.([]byte)
	default:
		return 0, fmt.Errorf("invalid DateAndTime type %v", pduType)
	}
	pduLength := len(v)
	// DateAndTime can be 8 or 11 bytes depending if the time zone is included.
	switch pduLength {
	case 5: // HP: YMDHM - so ancient => propably not UTC and day light saving
		if v[0] == 0 && v[1] == 0 && v[2] == 0 && v[3] == 0 && v[4] == 0 {
			return 0, nil
		}
		loc, _ := time.LoadLocation("Local")
		t := time.Date(2000 + int(v[0]), time.Month(v[1]), int(v[2]), int(v[3]), int(v[4]), 0, 0, loc)
		// Go time is a nightmare - what a bullshit compared to java
		offset := int64(timeLocalDelta)
		if t.IsDST() {
			offset -= 3600
		}
		return float64(t.Unix() - int64(offset)), nil
	case 7: // HP: YMDuHMS - so ancient => propably not UTC and day light saving
		if v[0] == 0 && v[1] == 0 && v[2] == 0 && v[3] == 0 && v[4] == 0 && v[5] == 0 && v[6] == 0 {
			return 0, nil
		}
		loc, _ := time.LoadLocation("Local")
		t := time.Date(2000 + int(v[0]), time.Month(v[1]), int(v[2]), int(v[4]), int(v[5]), int(v[6]), 0, loc)
		// Go time is a nightmare - what a bullshit compared to java
		offset := int64(timeLocalDelta)
		if t.IsDST() {
			offset -= 3600
		}
		return float64(t.Unix() - int64(offset)), nil
	case 8:
		// No time zone included, assume UTC.
		tz = time.UTC
	case 11:
		// Extract the timezone from the last 3 bytes.
		locString := fmt.Sprintf("%c%02d%02d", v[8], v[9], v[10])
		loc, err := time.Parse("-0700", locString)
		if err != nil {
			return 0, fmt.Errorf("error parsing DateAndTime location string: %q, error: %s", locString, err)
		}
		tz = loc.Location()
	default:
		return 0, fmt.Errorf("invalid DateAndTime length %v", pduLength)
	}
	if err != nil {
		return 0, fmt.Errorf("unable to parse DateAndTime %q, error: %s", v, err)
	}
	// Build the date from the various fields and time zone.
	t := time.Date(
		int(binary.BigEndian.Uint16(v[0:2])),
		time.Month(v[2]),
		int(v[3]),
		int(v[4]),
		int(v[5]),
		int(v[6]),
		int(v[7])*1e+8,
		tz)
	return float64(t.Unix()), nil
}

func pduToSamples(indexOids []int, pdu *gosnmp.SnmpPDU, metric *config.Metric, oidToPdu map[string]gosnmp.SnmpPDU, idxCache map[string]string, logger log.Logger, compact bool) []prometheus.Metric {
	var err error
	// The part of the OID that is the indexes.
	labels, subOid := indexesToLabels(indexOids, metric, pdu, oidToPdu, idxCache, logger)
	_, ok := labels["@drop@"]
	if ok {
		return []prometheus.Metric{}
	}

	newName := metric.Name
	if len(subOid) == 0 {
		i := strings.LastIndexByte(metric.Oid, '.')
		if i != -1 {
			subOid = metric.Oid[i+1:]
		}
	}
    if len(metric.Rename) != 0 && len(subOid) != 0 {
		for _, e := range metric.Rename {
			if e.SubOids == nullRegexp {
				continue
			}
			idx := e.SubOids.FindStringIndex(subOid)
			if idx != nil {
				newName = e.Value;
				break;
			}
		}
	}

	value := getPduValue(pdu)
	t := prometheus.UntypedValue

	labelnames := make([]string, 0, len(labels)+1)
	labelvalues := make([]string, 0, len(labels)+1)
	for k, v := range labels {
		labelnames = append(labelnames, k)
		labelvalues = append(labelvalues, v)
	}

	needRemap := len(metric.Remap) != 0
	hasRegex := len(metric.RegexpExtracts) != 0
	switch metric.Type {
	case "counter":
		t = prometheus.CounterValue
	case "uptime":
		t = prometheus.CounterValue
		n := - int64(value)
		if pdu.Type == 0x43 {
			n /= 100		// Timeticks are usally given in 100 Hz
		}
		n += time.Now().Unix()
		value = float64(n - (n & 1))	// n % 2 == n & 1
	case "gauge":
		t = prometheus.GaugeValue
	case "Float", "Double":
		t = prometheus.GaugeValue
	case "DateAndTime":
		t = prometheus.GaugeValue
		value, err = parseDateAndTime(pdu)
		if err != nil {
			level.Warn(logger).Log("msg", err, "metric", metric.Name)
			return []prometheus.Metric{}
		}
	case "EnumAsInfo":
		return enumAsInfo(metric, newName, int(value), labelnames, labelvalues, compact)
	case "EnumAsStateSet":
		return enumAsStateSet(metric, newName, int(value), labelnames, labelvalues, compact)
	case "Bits":
		return bits(metric, newName, pdu.Value, labelnames, labelvalues, compact)
	default:
		// It's some form of string.
		t = prometheus.GaugeValue
		value = 1.0
		metricType := metric.Type

		if typeMapping, ok := combinedTypeMapping[metricType]; ok {
			// Lookup associated sub type in previous object.
			oids := strings.Split(metric.Oid, ".")
			i, _ := strconv.Atoi(oids[len(oids)-1])
			oids[len(oids)-1] = strconv.Itoa(i - 1)
			prevOid := fmt.Sprintf("%s.%s", strings.Join(oids, "."), listToOid(indexOids))
			if prevPdu, ok := oidToPdu[prevOid]; ok {
				val := int(getPduValue(&prevPdu))
				if t, ok := typeMapping[val]; ok {
					metricType = t
				} else {
					metricType = "OctetString"
	if DebugEnabled {
					level.Debug(logger).Log("msg", "Unable to handle type value", "value", val, "oid", prevOid, "metric", newName)
	}
				}
			} else {
				metricType = "OctetString"
	if DebugEnabled {
				level.Debug(logger).Log("msg", "Unable to find type at oid for metric", "oid", prevOid, "metric", newName)
	}
			}
		}

		if hasRegex {
			return applyRegexExtracts(metric, newName, subOid, strings.TrimSpace(pduValueAsString(pdu, metricType)), labelnames, labelvalues, logger, compact)
		}
		s := strings.TrimSpace(pduValueAsString(pdu, metricType))
		// Put in the value as a label with the same name as the metric.
		addLabel := true
		if needRemap {
			v , x := metric.Remap[s]
			if x {
				if v == "@drop@" {
					return []prometheus.Metric{}
				}
				s = v
				f, err := strconv.ParseFloat(v, 64)
				if err == nil {
					value = f
					addLabel = false
				}
			}
		}
		needRemap = false
		if addLabel {
			// unlikely that it is already there
			labelnames = append(labelnames, newName)
			labelvalues = append(labelvalues, s)
		}
	}

	help := ""
	if ! compact {
		help = metric.Help
	}
    if hasRegex {
		return applyRegexExtracts(metric, newName, subOid, strconv.FormatFloat(value, 'f', -1, 64), labelnames, labelvalues, logger, compact)
	}
	if needRemap {
		v, ok := metric.Remap[strconv.FormatFloat(value, 'f', -1, 64)]
		if ok {
			if v == "@drop@" {
				return []prometheus.Metric{}
			}
			f, err := strconv.ParseFloat(v, 64)
			if err == nil {
				value = f
			} else {
				// unlikely that it is already there
				labelnames = append(labelnames, newName)
				labelvalues = append(labelvalues, v)
				// value = 1.0	// not resetting it allows more flexebility
			}
		}
	}
	sample, err := prometheus.NewConstMetric(prometheus.NewDesc(newName, help, labelnames, nil),
		t, value, labelvalues...)
	if err != nil {
		sample = prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "Error calling NewConstMetric", nil, nil),
			fmt.Errorf("error for metric %s with labels %v from indexOids %v: %v", newName, labelvalues, indexOids, err))
	}

	return []prometheus.Metric{sample}
}

func applyRegexExtracts(metric *config.Metric, mName string, subOids string, pduValue string, labelnames, labelvalues []string, logger log.Logger, compact bool) []prometheus.Metric {
	results := []prometheus.Metric{}
	help := ""
	if ! compact {
		help = metric.Help + " (regex extracted)"
	}

	for name, strMetricSlice := range metric.RegexpExtracts {
		var newName string
		if len(name) > 0 && name[0] == '.' {
			newName = name[1:]
		} else {
			newName = mName + name
		}
		for _, strMetric := range strMetricSlice {
			if strMetric.SubOids != nullRegexp {
				idx := strMetric.SubOids.FindStringIndex(subOids)
				if idx == nil {
					continue
				}
			}
			indexes := strMetric.Regex.FindStringSubmatchIndex(pduValue)
			if (indexes == nil && !strMetric.Invert) || (indexes != nil && strMetric.Invert) {
	if DebugEnabled {
				level.Debug(logger).Log("msg", "No regex match", "metric", newName, "value", pduValue, "regex", strMetric.Regex.String(), "invert", strMetric.Invert)
	}
				continue
			}
			res := strMetric.Regex.ExpandString([]byte{}, strMetric.Value, pduValue, indexes)
			s := string(res)
			t, ok := metric.Remap[s]
			if ok {
				s = t
			}
			if s == "@drop@" {
	if DebugEnabled {
				level.Debug(logger).Log("msg", "Dropping metric", "metric", newName, "value", pduValue, "regex", strMetric.Regex.String(), "extracted_value", res)
	}
				return []prometheus.Metric{}
			}
			v, err := strconv.ParseFloat(s, 64)
			if err != nil {
	if DebugEnabled {
				level.Debug(logger).Log("msg", "Error parsing float64 from value", "metric", newName, "value", pduValue, "regex", strMetric.Regex.String(), "extracted_value", res)
	}
				labelnames = append(labelnames, newName)
				labelvalues = append(labelvalues, s)
				v = 1.0
			}
			newMetric, err := prometheus.NewConstMetric(prometheus.NewDesc(newName, help, labelnames, nil),
				prometheus.GaugeValue, v, labelvalues...)
			if err != nil {
				newMetric = prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "Error calling NewConstMetric for regex_extract", nil, nil),
					fmt.Errorf("error for metric %s with labels %v: %v", newName+name, labelvalues, err))
			}
			results = append(results, newMetric)
			break
		}
	}
	return results
}

func enumAsInfo(metric *config.Metric, newName string, value int, labelnames, labelvalues []string, compact bool) []prometheus.Metric {
	// Lookup enum, default to the value.
	state, ok := metric.EnumValues[int(value)]
	if !ok {
		state = strconv.Itoa(int(value))
	}
	t, ok := metric.Remap[state]
	if ok {
		if t == "@drop@" {
			return []prometheus.Metric{}
		}
		state = t
	}
	labelnames = append(labelnames, newName)
	labelvalues = append(labelvalues, state)

	help := ""
	if ! compact {
		help = metric.Help + " (EnumAsInfo)"
	}
	newMetric, err := prometheus.NewConstMetric(prometheus.NewDesc(newName+"_info", help, labelnames, nil),
		prometheus.GaugeValue, 1.0, labelvalues...)
	if err != nil {
		newMetric = prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "Error calling NewConstMetric for EnumAsInfo", nil, nil),
			fmt.Errorf("error for metric %s with labels %v: %v", newName, labelvalues, err))
	}
	return []prometheus.Metric{newMetric}
}

func enumAsStateSet(metric *config.Metric, newName string, value int, labelnames, labelvalues []string, compact bool) []prometheus.Metric {
	labelnames = append(labelnames, newName)
	results := []prometheus.Metric{}

	state, ok := metric.EnumValues[value]
	if !ok {
		// Fallback to using the value.
		state = strconv.Itoa(value)
	}
	t, ok := metric.Remap[state]
	if ok {
		if t == "@drop@" {
			return []prometheus.Metric{}
		}
		state = t
	}
	help := ""
	if ! compact {
		help = metric.Help + " (EnumAsStateSet)"
	}
	newMetric, err := prometheus.NewConstMetric(prometheus.NewDesc(newName, help, labelnames, nil),
		prometheus.GaugeValue, 1.0, append(labelvalues, state)...)
	if err != nil {
		newMetric = prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "Error calling NewConstMetric for EnumAsStateSet", nil, nil),
			fmt.Errorf("error for metric %s with labels %v: %v", newName, labelvalues, err))
	}
	results = append(results, newMetric)

	for k, v := range metric.EnumValues {
		if k == value {
			continue
		}
		t, ok := metric.Remap[v]
		if ok {
			if t == "@drop@" {
				continue
			}
			v = t
		}
		newMetric, err := prometheus.NewConstMetric(prometheus.NewDesc(newName, help, labelnames, nil),
			prometheus.GaugeValue, 0.0, append(labelvalues, v)...)
		if err != nil {
			newMetric = prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "Error calling NewConstMetric for EnumAsStateSet", nil, nil),
				fmt.Errorf("error for metric %s with labels %v: %v", newName, labelvalues, err))
		}
		results = append(results, newMetric)
	}
	return results
}

func bits(metric *config.Metric, newName string, value interface{}, labelnames, labelvalues []string, compact bool) []prometheus.Metric {
	bytes, ok := value.([]byte)
	if !ok {
		return []prometheus.Metric{prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "BITS type was not a BISTRING on the wire.", nil, nil),
			fmt.Errorf("error for metric %s with labels %v: %T", newName, labelvalues, value))}
	}
	labelnames = append(labelnames, newName)
	results := []prometheus.Metric{}

	help := ""
	if ! compact {
		help = metric.Help + " (Bits)"
	}
	for k, v := range metric.EnumValues {
		bit := 0.0
		// Most significant byte most significant bit, then most significant byte 2nd most significant bit etc.
		if k < len(bytes)*8 {
			if (bytes[k/8] & (128 >> (k % 8))) != 0 {
				bit = 1.0
			}
		}
		newMetric, err := prometheus.NewConstMetric(prometheus.NewDesc(newName, help, labelnames, nil),
			prometheus.GaugeValue, bit, append(labelvalues, v)...)
		if err != nil {
			newMetric = prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "Error calling NewConstMetric for Bits", nil, nil),
				fmt.Errorf("error for metric %s with labels %v: %v", newName, labelvalues, err))
		}
		results = append(results, newMetric)
	}
	return results
}

// Right pad oid with zeros, and split at the given point.
// Some routers exclude trailing 0s in responses.
func splitOid(oid []int, count int) ([]int, []int) {
	head := make([]int, count)
	tail := []int{}
	for i, v := range oid {
		if i < count {
			head[i] = v
		} else {
			tail = append(tail, v)
		}
	}
	return head, tail
}

// This mirrors decodeValue in gosnmp's helper.go.
func pduValueAsString(pdu *gosnmp.SnmpPDU, typ string) string {
	switch pdu.Value.(type) {
	case int:
		return strconv.Itoa(pdu.Value.(int))
	case uint:
		return strconv.FormatUint(uint64(pdu.Value.(uint)), 10)
	case uint64:
		return strconv.FormatUint(pdu.Value.(uint64), 10)
	case float32:
		return strconv.FormatFloat(float64(pdu.Value.(float32)), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(pdu.Value.(float64), 'f', -1, 64)
	case string:
		if pdu.Type == gosnmp.ObjectIdentifier {
			// Trim leading period.
			return pdu.Value.(string)[1:]
		}
		// DisplayString.
		return pdu.Value.(string)
	case []byte:
		if typ == "" {
			typ = "OctetString"
		}
		// Reuse the OID index parsing code.
		parts := make([]int, len(pdu.Value.([]byte)))
		for i, o := range pdu.Value.([]byte) {
			parts[i] = int(o)
		}
		if typ == "OctetString" || typ == "DisplayString" {
			// Prepend the length, as it is explicit in an index.
			parts = append([]int{len(pdu.Value.([]byte))}, parts...)
		}
		str, _, _ := indexOidsAsString(parts, typ, 0, false, nil)
		return str
	case nil:
		return ""
	default:
		// This shouldn't happen.
		snmpUnexpectedPduType.Inc()
		return fmt.Sprintf("%s", pdu.Value)
	}
}

// Convert oids to a string index value.
//
// Returns the string, the oids that were used and the oids left over.
func indexOidsAsString(indexOids []int, typ string, fixedSize int, implied bool, enumValues map[int]string) (string, []int, []int) {
	if typeMapping, ok := combinedTypeMapping[typ]; ok {
		subOid, valueOids := splitOid(indexOids, 2)
		if typ == "InetAddressMissingSize" {
			// The size of the main index value is missing.
			subOid, valueOids = splitOid(indexOids, 1)
		}
		var str string
		var used, remaining []int
		if t, ok := typeMapping[subOid[0]]; ok {
			str, used, remaining = indexOidsAsString(valueOids, t, 0, false, enumValues)
			return str, append(subOid, used...), remaining
		}
		if typ == "InetAddressMissingSize" {
			// We don't know the size, so pass everything remaining.
			return indexOidsAsString(indexOids, "OctetString", 0, true, enumValues)
		}
		// The 2nd oid is the length.
		return indexOidsAsString(indexOids, "OctetString", subOid[1]+2, false, enumValues)
	}

	switch typ {
	case "Integer32", "Integer", "gauge", "counter", "uptime":
		// Extract the oid for this index, and keep the remainder for the next index.
		subOid, indexOids := splitOid(indexOids, 1)
		return fmt.Sprintf("%d", subOid[0]), subOid, indexOids
	case "PhysAddress48":
		subOid, indexOids := splitOid(indexOids, 6)
		parts := make([]string, 6)
		for i, o := range subOid {
			parts[i] = fmt.Sprintf("%02X", o)
		}
		return strings.Join(parts, ":"), subOid, indexOids
	case "OctetString":
		var subOid []int
		// The length of fixed size indexes come from the MIB.
		// For varying size, we read it from the first oid.
		length := fixedSize
		if implied {
			length = len(indexOids)
		}
		if length == 0 {
			subOid, indexOids = splitOid(indexOids, 1)
			length = subOid[0]
		}
		content, indexOids := splitOid(indexOids, length)
		subOid = append(subOid, content...)
		parts := make([]byte, length)
		for i, o := range content {
			parts[i] = byte(o)
		}
		if len(parts) == 0 {
			return "", subOid, indexOids
		} else {
			return fmt.Sprintf("0x%X", string(parts)), subOid, indexOids
		}
	case "DisplayString":
		var subOid []int
		length := fixedSize
		if implied {
			length = len(indexOids)
		}
		if length == 0 {
			subOid, indexOids = splitOid(indexOids, 1)
			length = subOid[0]
		}
		content, indexOids := splitOid(indexOids, length)
		subOid = append(subOid, content...)
		parts := make([]byte, length)
		for i, o := range content {
			parts[i] = byte(o)
		}
		// ASCII, so can convert staight to utf-8.
		return string(parts), subOid, indexOids
	case "InetAddressIPv4":
		subOid, indexOids := splitOid(indexOids, 4)
		parts := make([]string, 4)
		for i, o := range subOid {
			parts[i] = strconv.Itoa(o)
		}
		return strings.Join(parts, "."), subOid, indexOids
	case "InetAddressIPv6":
		subOid, indexOids := splitOid(indexOids, 16)
		parts := make([]interface{}, 16)
		for i, o := range subOid {
			parts[i] = o
		}
		return fmt.Sprintf("%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X", parts...), subOid, indexOids
	case "EnumAsInfo":
		subOid, indexOids := splitOid(indexOids, 1)
		value, ok := enumValues[subOid[0]]
		if ok {
			return value, subOid, indexOids
		} else {
			return fmt.Sprintf("%d", subOid[0]), subOid, indexOids
		}
	default:
		panic(fmt.Sprintf("Unknown index type %s", typ))
		return "", nil, nil
	}
}

func indexesToLabels(indexOids []int, metric *config.Metric, pdu *gosnmp.SnmpPDU, oidToPdu map[string]gosnmp.SnmpPDU, idxCache map[string]string, logger log.Logger) (map[string]string, string) {
	labels := map[string]string{}
	labelSubOids := map[string][]int{}
	subOids := ""

	// Prepare index info for the source indexes to lookup
	poid := ""
	for _, index := range metric.Indexes {
		if index.Labelname == "_idx" {
			if pdu == nil {
				continue
			}
	if DebugEnabled {
			level.Debug(logger).Log("indexOids", fmt.Sprintf("%v", indexOids), "moid", metric.Oid, "poid", pdu.Name[1:])
	}
			oid := metric.Oid
			poid = pdu.Name[1:]	//drop the leading .
			if strings.HasSuffix(poid, ".0") {
				poid = poid[:len(poid)-2]
			}
			i := -1
			if len(poid) < len(oid) {
				continue
			} else if len(poid) == len(oid) {
				i = strings.LastIndexByte(poid, '.')
				i = strings.LastIndexByte(poid[:i], '.')
			} else {
				i = len(oid)
			}
			s := poid[i+1:]
			subOids += "." + s
			idxCache[poid] = s
			continue
		}
		str, subOid, tail := indexOidsAsString(indexOids, index.Type,
			index.FixedSize, index.Implied, index.EnumValues)
		// The text form of the subOid to lookup. Here it is the table row
		// [index] to lookup. Usually nameToOid[index.Labelname] + "." + str
		// would be the real OID one would need to lookup.
		if index.IsNative {
			labels[index.Labelname] = str
			labelSubOids[index.Labelname] = subOid
			// this allows us to skip fetching the index2index table
			n := listToOid(subOid)
			idxCache[index.Oid + "." + n] = n

	// go-kit logging crap is slow as hell
	if DebugEnabled {
			level.Debug(logger).Log("idxCacheNativ", index.Oid  + "." + n, "value", n)
	}
		} else {
			labelSubOids[index.Oid] = indexOids
	if DebugEnabled {
			level.Debug(logger).Log("idxCachePseudo", index.Oid, "value", listToOid(subOid))
	}
		}
		if len(str) != 0 {
			subOids += "." + str
		}
		// remaining subOids to lookup
		indexOids = tail
	}
	if len(subOids) != 0 {
		subOids = subOids[1:]
	}

	// Perform lookups.
	for _, lookup := range metric.Lookups {
		if len(lookup.Labels) == 0 && ! lookup.Inject {
			// Lookups without labels are those tagged with drop_source_indexes
			for _, label := range lookup.Labelname {
				delete(labels, label)
			}
			continue
		}
		if lookup.SubOids != nullRegexp {
			idx := lookup.SubOids.FindStringIndex(subOids)
			if idx == nil {
				continue
			}
		}
		applyRevalue := true
		if len(lookup.Labelvalue.Value) != 0 {
			if lookup.Labelvalue.SubOids != nullRegexp {
				idx := lookup.Labelvalue.SubOids.FindStringIndex(subOids)
				applyRevalue = idx != nil
	if DebugEnabled {
				level.Debug(logger).Log("subOid_match", applyRevalue, "subOid", subOids, "regex", lookup.Labelvalue.SubOids.String())
	}
			} else {
	if DebugEnabled {
				level.Debug(logger).Log("subOid_match", "skip")
	}
			}
		} else {
	if DebugEnabled {
			level.Debug(logger).Log("subOid_match", "skip")
	}
			applyRevalue = false
		}
		last := len(lookup.Oid) - 1
		for c, oid := range lookup.Oid {
			boid := oid	// just save for debug statement below
			if oid == "0" {
				oid = poid
			} else if lookup.Inject && c == 0 {
				oid = fmt.Sprintf("%s.%s", oid, listToOid(labelSubOids[lookup.Oid[c]]))
				if strings.HasSuffix(oid, ".") {
					oid = fmt.Sprintf("%s%s", oid, subOids)
					labelSubOids[lookup.Oid[c]] = indexOids
				}
			} else if c == 0 {
				// in the first round, lookup the [multi] index
				for _, label := range lookup.Labels {
					oid = fmt.Sprintf("%s.%s", oid, listToOid(labelSubOids[label]))
				}
			} else {
					oid = fmt.Sprintf("%s.%s", oid, listToOid(labelSubOids[lookup.Labelname[c]]))
			}
			s := idxCache[oid]
			pdu, ok := oidToPdu[oid]
	if DebugEnabled {
			level.Debug(logger).Log("BaseOid", boid, "lookup", lookup.Labelname[c], "lookupOid", oid, "subOid", subOids, "cache", s, "PDU_found", ok, "Inject", lookup.Inject)
	}
			if ok || len(s) != 0 || lookup.Inject {
				var typ  string
				if len(lookup.Type) != 0 {
					typ = lookup.Type[c]
				}

				if len(s) == 0  && ok {
					s = strings.TrimSpace(pduValueAsString(&pdu, typ))
	if DebugEnabled {
					level.Debug(logger).Log("PDU_value", s)
	}
					idxCache[oid] = s
				}
				if applyRevalue && c == last {
					t := s
					indexes := lookup.Labelvalue.Regex.FindStringSubmatchIndex(s)
					if (indexes != nil && !lookup.Labelvalue.Invert) || (indexes == nil && lookup.Labelvalue.Invert) {
						s = string(lookup.Labelvalue.Regex.ExpandString([]byte{}, lookup.Labelvalue.Value, t, indexes))
	if DebugEnabled {
						level.Debug(logger).Log("revalue_metric", metric.Name, "label", lookup.Labelname[c], "old", t, "new", s, "invert", lookup.Labelvalue.Invert)
	}
					}
				}
				if lookup.Remap != nil {
					v, x := lookup.Remap[s]
					if x {
	if DebugEnabled {
						level.Debug(logger).Log("remap_metric", metric.Name, "label", lookup.Labelname[c], "old", s, "new", v)
	}
						s = v
					}
				}
				if lookup.SubOidRemap != nil {
					v, x := lookup.SubOidRemap[subOids + ";" + s]
					if x {
	if DebugEnabled {
						level.Debug(logger).Log("remap_metric", metric.Name, "label", lookup.Labelname[c], "old", subOids + ";" + s, "new", v)
	}
						s = v
					}
				}
				if s == "@drop@" {
					// drop the metric
					labels["@drop@"] = "drop"
					return labels , subOids
				}
				if len(s) != 0 {
	if DebugEnabled {
					level.Debug(logger).Log("Action", "inject", "label", lookup.Labelname[c], "value", s)
	}
					labels[lookup.Labelname[c]] = s
				} else {
	if DebugEnabled {
					level.Debug(logger).Log("Action", "delete", "label", lookup.Labelname[c])
	}
					delete(labels, lookup.Labelname[c])
				}
				if ok {
					a := []int{int(gosnmp.ToBigInt(pdu.Value).Int64())}
					labelSubOids[lookup.Labelname[c]] = a	// for chaining
					if (c < last) && (! lookup.Inject) {
						labelSubOids[lookup.Labelname[c+1]] = a
					}
				}
	if DebugEnabled {
				level.Debug(logger).Log("--------------------------------------------------", "")
	}
			}
		}
	}

	if DebugEnabled {
		level.Debug(logger).Log("Labels-done-", "-->", "metric", metric.Name, "labels", fmt.Sprintf("%v", labels))
	}

	return labels, subOids
}
