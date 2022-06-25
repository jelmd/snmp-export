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
//
// Copyright 2022 Jens Elkner (jel+snmp-exporter@cs.uni-magdeburg.de)
// All rights reserved.

package main

import (
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var debug = flag.Bool("d", false, "enable debug output")

func compare(a []string, b []string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil || len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// go test -v -run TestExpandOverrides [-args -d]
func TestExpandOverrides(t *testing.T) {
	tests := [][]string{
		{"abc¦def¦ghi", "abc¦def¦ghi"},
		{"a{a..d}z", "aaz¦abz¦acz¦adz"},
		{"foo{bar,sel,l}", "foobar¦foosel¦fool"},
		{"chapter{A..F}.1", "chapterA.1¦chapterB.1¦chapterC.1¦chapterD.1¦chapterE.1¦chapterF.1"},
		{"{a,z}{1..5..3%02d}{b..c}x", "a01bx¦a01cx¦a04bx¦a04cx¦z01bx¦z01cx¦z04bx¦z04cx"},
		{"ff{c,b,a}", "ffc¦ffb¦ffa"},
		{"f{d,e,f}g", "fdg¦feg¦ffg"},
		{"{l,n,m}xyz", "lxyz¦nxyz¦mxyz"},
		{"{abc\\,def}", "abc\\¦def"},
		{"{abc,def}", "abc¦def"},
		{"{\"abc,def\"}", "\"abc¦def\""},
		{"{'abc,def'}", "'abc¦def'"},
		{"{abc}", "abc"},
		{"\\{a,b,c,d,e}", "\\{a,b,c,d,e}"},
		{"{x,y,\\{a,b,c}}", "x}¦y}¦\\{a}¦b}¦c}"},
		{"{x\\,y,\\{abc\\},trie}", "x\\¦y¦\\{abc\\}¦trie"},
		{"/usr/{ucb/{ex,edit},lib/{ex,how_ex}}", "/usr/ucb/ex¦/usr/ucb/edit¦/usr/lib/ex¦/usr/lib/how_ex"},
		{"XXXX\\{a,b,c\\}", "XXXX\\{a,b,c\\}"},
		{"{}", ""},
		{"{ }", " "},
		{"}", "}"},
		{"{", "{"},
		{"abcd{efgh", "abcd{efgh"},
		{"foo {1,2} bar", "foo 1 bar¦foo 2 bar"},
		{"{1..10}", "1¦2¦3¦4¦5¦6¦7¦8¦9¦10"},
		{"{0..10,braces}", "0..10¦braces"},
		{"{{0..10},braces}", "0¦1¦2¦3¦4¦5¦6¦7¦8¦9¦10¦braces"},
		{"x{{0..10},braces}y", "x0y¦x1y¦x2y¦x3y¦x4y¦x5y¦x6y¦x7y¦x8y¦x9y¦x10y¦xbracesy"},
		{"3..3", "3..3"},
		{"{3..3}", "3"},
		{"x{3..3}y", "x3y"},
		{"{10..1}", "10¦9¦8¦7¦6¦5¦4¦3¦2¦1"},
		{"{10..1}y", "10y¦9y¦8y¦7y¦6y¦5y¦4y¦3y¦2y¦1y"},
		{"x{10..1}y", "x10y¦x9y¦x8y¦x7y¦x6y¦x5y¦x4y¦x3y¦x2y¦x1y"},
		{"{a..f}", "a¦b¦c¦d¦e¦f"},
		{"{f..a}", "f¦e¦d¦c¦b¦a"},
		{"{a..A}", "a..A"},
		{"{A..a}", "A..a"},
		{"{f..f}", "f"},
		{"{1..f}", "1..f"},
		{"{f..1}", "f..1"},
		{"{0{1..9},{10..20}}", "01¦02¦03¦04¦05¦06¦07¦08¦09¦10¦11¦12¦13¦14¦15¦16¦17¦18¦19¦20"},
		{"{-1..-10}", "-1¦-2¦-3¦-4¦-5¦-6¦-7¦-8¦-9¦-10"},
		{"{-19..0}", "-19¦-18¦-17¦-16¦-15¦-14¦-13¦-12¦-11¦-10¦-9¦-8¦-7¦-6¦-5¦-4¦-3¦-2¦-1¦0"},
		{"{0..10}", "0¦1¦2¦3¦4¦5¦6¦7¦8¦9¦10"},
		{"{0..10..1}", "0¦1¦2¦3¦4¦5¦6¦7¦8¦9¦10"},
		{"{0..10..2}", "0¦2¦4¦6¦8¦10"},
		{"{0..10..3}", "0¦3¦6¦9"},
		{"{0..10..0}", "0..10..0"},
		{"{0..10..-1}", "0"},
		{"{10..0}", "10¦9¦8¦7¦6¦5¦4¦3¦2¦1¦0"},
		{"{10..0..-1}", "10¦9¦8¦7¦6¦5¦4¦3¦2¦1¦0"},
		{"{10..0..-2}", "10¦8¦6¦4¦2¦0"},
		{"{10..0..-3}", "10¦7¦4¦1"},
		{"{10..0..0}", "10..0..0"},
		{"{10..0..1}", "10"},
		{"{a..z..2}", "a¦c¦e¦g¦i¦k¦m¦o¦q¦s¦u¦w¦y"},
		{"{y..b..-3}", "y¦v¦s¦p¦m¦j¦g¦d"},
		{"{0..0x1000..0x200}", "0¦512¦1024¦1536¦2048¦2560¦3072¦3584¦4096"},
		{"{a,b}{0..2}{z,y}", "a0z¦a0y¦a1z¦a1y¦a2z¦a2y¦b0z¦b0y¦b1z¦b1y¦b2z¦b2y"},
		{"{0..0100..8%03o}", "000¦010¦020¦030¦040¦050¦060¦070¦100"},
		{"{0..0100..040%020o}", "00000000000000000000¦00000000000000000040¦00000000000000000100"},
		{"{0..7%03b}", "000¦001¦010¦011¦100¦101¦110¦111"},
		{"{0..10%llu}", "0..10%llu"},
		{"{0..10%s}", "0..10%s"},
		{"{0..10%dl}", "0l¦1l¦2l¦3l¦4l¦5l¦6l¦7l¦8l¦9l¦10l"},
		{"{a,b}{0..3%02b}{y,z}", "a00y¦a00z¦a01y¦a01z¦a10y¦a10z¦a11y¦a11z¦b00y¦b00z¦b01y¦b01z¦b10y¦b10z¦b11y¦b11z"},
		{"{a..c}.{0..9}", "a.0¦a.1¦a.2¦a.3¦a.4¦a.5¦a.6¦a.7¦a.8¦a.9¦b.0¦b.1¦b.2¦b.3¦b.4¦b.5¦b.6¦b.7¦b.8¦b.9¦c.0¦c.1¦c.2¦c.3¦c.4¦c.5¦c.6¦c.7¦c.8¦c.9"},
		{"consumable-{current-state,life-{low-threshold,usage-units{,remaining}},pages-printed-with-supply,status-{capacity-units,cartridge-model,developer-life{,-units},drum-life{,-units},engine-{job-count,usage-{count,units}},first-install-date,formatter-color-page-count,info,last-use-date,manufacturer-name,manufacturing-date,oem-name,printer-design-compatibility,serial-number,tls-max-value,total-capacity,total-equiv-page-count,total-page-count,usage-{count,units},web-service-access-{control,data}}}", "consumable-current-state¦consumable-life-low-threshold¦consumable-life-usage-units¦consumable-life-usage-unitsremaining¦consumable-pages-printed-with-supply¦consumable-status-capacity-units¦consumable-status-cartridge-model¦consumable-status-developer-life¦consumable-status-developer-life-units¦consumable-status-drum-life¦consumable-status-drum-life-units¦consumable-status-engine-job-count¦consumable-status-engine-usage-count¦consumable-status-engine-usage-units¦consumable-status-first-install-date¦consumable-status-formatter-color-page-count¦consumable-status-info¦consumable-status-last-use-date¦consumable-status-manufacturer-name¦consumable-status-manufacturing-date¦consumable-status-oem-name¦consumable-status-printer-design-compatibility¦consumable-status-serial-number¦consumable-status-tls-max-value¦consumable-status-total-capacity¦consumable-status-total-equiv-page-count¦consumable-status-total-page-count¦consumable-status-usage-count¦consumable-status-usage-units¦consumable-status-web-service-access-control¦consumable-status-web-service-access-data"},
		{"input-tray-{min,max}-media-{,x}feed-dima", "input-tray-min-media-feed-dima¦input-tray-min-media-xfeed-dima¦input-tray-max-media-feed-dima¦input-tray-max-media-xfeed-dima"},
		{"{test,input-tray-{min,max}-media-{,x}feed-dima}", "test¦input-tray-min-media-feed-dima¦input-tray-min-media-xfeed-dima¦input-tray-max-media-feed-dima¦input-tray-max-media-xfeed-dima"},
		{"{custom-paper-{,x}feed-dim,destination-bin-usage-count,estimated-page-yield{,-unit},input-tray-{min,max}-media-{,x}feed-dima}", "custom-paper-feed-dim¦custom-paper-xfeed-dim¦destination-bin-usage-count¦estimated-page-yield¦estimated-page-yield-unit¦input-tray-min-media-feed-dima¦input-tray-min-media-xfeed-dima¦input-tray-max-media-feed-dima¦input-tray-max-media-xfeed-dima"},
		{"custom-paper-{,x}feed-dim,destination-bin-usage-count,estimated-page-yield{,-unit},input-tray-{min,max}-media-{,x}feed-dima", "custom-paper-feed-dim,destination-bin-usage-count,estimated-page-yield,input-tray-min-media-feed-dima¦custom-paper-feed-dim,destination-bin-usage-count,estimated-page-yield,input-tray-min-media-xfeed-dima¦custom-paper-feed-dim,destination-bin-usage-count,estimated-page-yield,input-tray-max-media-feed-dima¦custom-paper-feed-dim,destination-bin-usage-count,estimated-page-yield,input-tray-max-media-xfeed-dima¦custom-paper-feed-dim,destination-bin-usage-count,estimated-page-yield-unit,input-tray-min-media-feed-dima¦custom-paper-feed-dim,destination-bin-usage-count,estimated-page-yield-unit,input-tray-min-media-xfeed-dima¦custom-paper-feed-dim,destination-bin-usage-count,estimated-page-yield-unit,input-tray-max-media-feed-dima¦custom-paper-feed-dim,destination-bin-usage-count,estimated-page-yield-unit,input-tray-max-media-xfeed-dima¦custom-paper-xfeed-dim,destination-bin-usage-count,estimated-page-yield,input-tray-min-media-feed-dima¦custom-paper-xfeed-dim,destination-bin-usage-count,estimated-page-yield,input-tray-min-media-xfeed-dima¦custom-paper-xfeed-dim,destination-bin-usage-count,estimated-page-yield,input-tray-max-media-feed-dima¦custom-paper-xfeed-dim,destination-bin-usage-count,estimated-page-yield,input-tray-max-media-xfeed-dima¦custom-paper-xfeed-dim,destination-bin-usage-count,estimated-page-yield-unit,input-tray-min-media-feed-dima¦custom-paper-xfeed-dim,destination-bin-usage-count,estimated-page-yield-unit,input-tray-min-media-xfeed-dima¦custom-paper-xfeed-dim,destination-bin-usage-count,estimated-page-yield-unit,input-tray-max-media-feed-dima¦custom-paper-xfeed-dim,destination-bin-usage-count,estimated-page-yield-unit,input-tray-max-media-xfeed-dima"},
		{"job-info-accounting-{{black,cyan,magenta,yellow}-dots,{color,grayscale}-impression-count,job-type,media-{{duplex,simplex}-count,size,type}}", "job-info-accounting-black-dots¦job-info-accounting-cyan-dots¦job-info-accounting-magenta-dots¦job-info-accounting-yellow-dots¦job-info-accounting-color-impression-count¦job-info-accounting-grayscale-impression-count¦job-info-accounting-job-type¦job-info-accounting-media-duplex-count¦job-info-accounting-media-simplex-count¦job-info-accounting-media-size¦job-info-accounting-media-type"},
		{"custom-paper-{,x}feed-dim¦destination-bin-usage-count¦estimated-page-yield{,-unit}", "custom-paper-feed-dim¦custom-paper-xfeed-dim¦destination-bin-usage-count¦estimated-page-yield¦estimated-page-yield-unit"},
		{"input-tray-{min,max}-media-{,x}feed-dim", "input-tray-min-media-feed-dim¦input-tray-min-media-xfeed-dim¦input-tray-max-media-feed-dim¦input-tray-max-media-xfeed-dim"},
	}

	logger := log.NewLogfmtLogger(os.Stdout)
	if *debug {
		logger = level.NewFilter(logger, level.AllowDebug())
	} else {
		logger = level.NewFilter(logger, level.AllowInfo())
	}
	logger = log.With(logger, "caller", log.DefaultCaller)

	for i, ta := range tests {
		//if i != 68 { continue }
		l := expandCfgItem(ta[0], logger)
		r := strings.Split(ta[1], "¦")
		if compare(l, r) {
			t.Logf("(%02d) %s => %s", i, ta[0], strings.Join(l, "¦"))
		} else {
			t.Errorf("(%02d) %s failed. Got:\n\t%s\nExpected:\n\t%s\n", i, ta[0], strings.Join(l,"¦"), strings.Join(r, "¦"))
		}
	}
}
