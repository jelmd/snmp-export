# SNMP Export Config Generator

This generator named snmp-export-cfg uses NetSNMP to parse MIBs, and generates configs for the snmp-exporter using them.

## Running
Since this utility uses libnetsnmp, MIB lookups are made either according to the hardcoded default PATH or, if the environment variable MIBDIRS is set, according to its colon separated list of directories. It is recommended but not mandatory to use the MIBS comming with the snmp-export-cfg package. E.g.:

```sh
export MIBDIRS=/usr/share/snmp-export/mibs
snmp-export-cfg generate -f /usr/share/doc/snmp-export/generator.yml -o /tmp/snmp.yml
```

Per default the generator reads in from `generator.yml` and writes to `snmp.yml`.

Additional options are available, use the `help` command to see them.


## Input File Format

The following snippet shows the generic format of the generator input file, which unfortunately was choosen to follow the YAML spec junk. But, once you get annoyed enough by countless errors and whitespace counting/replacing, you may convert it to json format - Go langs yaml parser implementation accepts it as well.

BTW: remember that in yaml hell a list of something can be represented as `[ item1, item2, ... ]` as well as:
```
- item1
- item2
...
```

So you may encounter generator files which look different, but accomplish the same.

Below all lower-case only words are literals, all camel case words represent variable strings. Details wrt. the shown literals and variables are explained later.

```yaml
modules:

  moduleName:                              # Mandatory. At least one.

    walk:                                  # Mandatory with one or more:
      - OID
      - snmpObjectName
      ...
    version: snmpVersion                   # 1..3. Default: 2 (i.e. SNMPv2c)
    max_repetitions: intNumber             # Default: 25
    retries: intNumber                     # Default: 3
    timeout: numSeconds                    # Default: 5
    prefix: metricsPrefix                  # Default: ''

    auth:                                  # SNMP authentication parameters:
      community: communityName             #   SNMPv1 & v2c. Default: 'public'

                                           #   SNMPv3:
      security_level: secLevel             #   authPriv|authNoPriv|noAuthNoPriv. Default: "noAuthNoPriv"
      username: userName                   #   Mandatory.
      password: userPassword               #   auth[No]Priv: Mandatory.
      auth_protocol: authProto             #   auth[No]Priv: MD5|SHA|SHA224|SHA256|SHA384|SHA512. Default: "MD5"
      priv_protocol: privProto             #   authPriv: DES|AES|AES192|AES256. Default: "DES"
      priv_password: privPassword          #   authPriv: Mandatory.
      context_name: ctxName                #   Default: ''

    lookups:                               # Optional with one or more:
      - source_indexes:                    #   Mandatory with one or more:
        - indexName
        - indexOID
        ...
        mprefix:                           # Optional with one or more:
          - indexNamePrefix
          - indexOIDPrefix
          ...
        drop_source_indexes: boolVal       #   Default: false
        lookup: tableNameChain             #   Mandatory.
        rename: newIndexName               #   Default: '' (i.e. do not rename)
        revalue:                           #   Optional.
          regex: regexExpr                 #     Default: ''
          value: newValue                  #     Default: '$1'. Special value: `@drop@` .. drop metric on match.
          sub_oids: regexExpr              #     optional subOid filter.
        remap:                             #   Optional with one or more:
          key: val
          ...

    overrides:                             # Optional with one or more:
      metricName:                          #   Mandatory.
        ignore: boolVal                    #     Default: false
        type: newType                      #     Default: '' (i.e. keep type as is)
        regex_extracts:                    #     Optional with one or more:
          newSuffix:                       #       Default: '' (Special: leading `.` or `^`) with one or more:
            -  regex: regexExpr            #         Default: ''
               value: newValue             #         Default: '$1'. Special value: `@drop@` .. drop metric on match.
               sub_oids: regexExpr         #         optional subOid filter.
            ...
        remap:                             #     Optional with one or more:
          key: val
          ...
        rename:                            #     Optional with one or more:
          - sub_oids: regexExpr            #         Default: ''
            value: newValue                #         Default: '$1'.
          ...
```
The `generator.yml` example provides a coarse grained list of modules which might be useful to get in touch with the exporter and can be used as a starting point for a more fine grained configuration, which meets your needs and saves a lot of energy.

# How it works
The generator creates a configration for the exporter (an SNMP agent, which queries SNMP targets and translates obtained information into metrics in prometheus format) with just the information it needs to. Therefore only the generator depends on net-snmp libraries to parse the MIB to obtain the numeric OID (simply OID) and textual OID (snmp [object] name), its type (int32, int32, gauge, octet, displayString, etc.), possible index names for tables of the intended targets. The exporter is a fully standalone application wrt. SNMP (doesn't need any MIB or SNMP lib or tools) and is therefore pretty fast and frugal. From a prometheus client's point of view the smallest addressable unit is a *module*. When the exporter receives a `/snmp&module=moduleName` request, it queries the host passed in the `target` parameter of the request for all OIDs in the *walk* section of the module `moduleName` via snmpbulk requests to obtain the required information. The name of the related SNMP object (i.e. textual OID) gets translated into the metric name. If the related object is a table or are table entries, the names and value of its indexes defined within the MIB become the labels and value of the deduced metric. E.g.:

```
org          OBJECT IDENTIFIER ::= { iso 3 }  --  "iso" = 1
dod          OBJECT IDENTIFIER ::= { org 6 }
internet     OBJECT IDENTIFIER ::= { dod 1 }
mgmt         OBJECT IDENTIFIER ::= { internet 2 }
mib-2        OBJECT IDENTIFIER ::= { mgmt 1 }
interfaces   OBJECT IDENTIFIER ::= { mib-2 2 }
...
ifTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF IfEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "A list of interface entries..."
    ::= { interfaces 2 }

ifEntry OBJECT-TYPE
    SYNTAX      IfEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "An entry for a particular interface."
    INDEX   { ifIndex }
    ::= { ifTable 1 }

IfEntry ::=
    SEQUENCE {
        ifIndex                 InterfaceIndex,
        ifInOctets              Counter32,
        ifOutOctets             Counter32,
        ...
    }

ifIndex OBJECT-TYPE
    SYNTAX      InterfaceIndex
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "A unique value, greater than zero, for each interface..."
    ::= { ifEntry 1 }
...
```

This would generate metrics like:
```
ifIndex{ifIndex="83886080"} 83886080
ifIndex{ifIndex="369098752"} 369098752
ifIndex{ifIndex="369098753"} 369098753
...
ifInOctets{ifIndex="83886080"} 83886080
ifInOctets{ifIndex="369098752"} 369098752
ifInOctets{ifIndex="369098753"} 369098753
...
ifOutOctets{ifIndex="83886080"} 83886080
ifOutOctets{ifIndex="369098752"} 369098752
ifOutOctets{ifIndex="369098753"} 369098753
```

However, this might not what you want and thus the generator provides settings, which let you mangle the outcome. E.g. *overrides* to drop a metric or to modify its name or value, or *lookups* to modify the generated labels and values, e.g. to resolve the _ifIndex_ number into the interface name by looking up the _ifname_ with the same _ifIndex_ number. Wrt. the MIB the _ifname_ (1.3.6.1.2.1.31.1.1.1.1) is part of the table ifXTable (1.3.6.1.2.1.31.1.1) - the generator would automatically inject it into the *walk* list. So e.g. consider the following generator config file and the unmangled metrics above:
```
modules:
  cisco:
    walk:
      - ifTable
    overrides: &ifTable_overrides
      ifIndex:
        ignore: true
      ...
    lookups: &ifTable_lookups
      - source_indexes: [ifIndex]
        lookup: 1.3.6.1.2.1.31.1.1.1.1 # ifName
        #drop_source_indexes: true
```

This would result into something like this:
```
ifInOctets{ifIndex="83886080",ifName="Fa0"} 83886080
ifInOctets{ifIndex="369098752",ifName="Gi0/1"} 369098752
ifInOctets{ifIndex="369098753",ifName="Gi0/2"} 369098753
...
ifOutOctets{ifIndex="83886080",ifName="Fa0"} 83886080
ifOutOctets{ifIndex="369098752",ifName="Gi0/1"} 369098752
ifOutOctets{ifIndex="369098753",ifName="Gi0/2"} 369098753
...
```

Because there is no value for the ifIndex anymore, one may drop it by removing the comment sign `#` before the `drop_source_indexes` key within the generator config file. Furthermore to rename a label one may use the `lookup.rename` key, to modify its value, or to even drop the whole metric based on the index (alias label) value one may use the `lookup.revalue` key within *lookups*.


## modules
Just the anchor for all modules. The simplest module is just a name and a set of OIDs to walk.

## _moduleName_
The name of a module, the smallest "addressable" unit for a prometheus client.

## walk: _list_
List of OIDs and SNMP object names to walk via SNMP. NOTE that object names might be not unique within a MIB and therefore the generated config might not query the intended objects. If unsure, use OIDs instead. Basically if you do a something like `snmpbulkwalk -v 2c -c public -Pu -Pw -OX $targetIP $OID_or_Name` the object name shown after the double colon (`::`) becomes the name of the metric. If the related "table entry" (if any) has an `INDEX` definition all these indexes become the labels of the metric with the obtained index value set.


## version: _version_
SNMP version to use.  1 will use GETNEXT, 2 (stands for 2c) and 3 use GETBULK. For 2 you may need to change/set the community name to use, for 3 all the other authentication/encryption related paramaters.

## max\_repetitions: _intNumber_
How many objects to request with GET/GETBULK. May need to be reduced for buggy devices.

## retries: _intNumber_
How many times to retry a failed request.

## timeout: _numSeconds_
Timeout for each individual SNMP request.

## prefix: _metricsPrefix_
Ensures that each metric has the prefix _metricsPrefix_. If a metric doesn't have it already, its gets prepend the metric name. Per default no prefix will be used.

## auth
Authentication paramaters to use for SNMP requests. Depends on SNMP version in use. For v2c the *community* name is needed - usually *public* is used by most devices, so this is the default. For SNMP v3 the required parameters depend on the choosen *security_level*.

### security\_level: _secLevel_
The security level to use for SNMP v3 requests (same as "-l _secLevel_" for net-snmp), so `noAuthNoPriv` (default), `authNoPriv` or `authPriv`.

### username: _userName_
The username to use for SNMPv3 requests (same as "-u _userName_" for net-snmp).

### password: _userPassword_
The password aka authKey to use for SNMPv3 requests (same as "-A _userPassword_" for net-snmp). Required for `authNoPriv` or `authPriv`.

### auth\_protocol: _authProto_
The protocol to use for authentication for SNMPv3 requests with security levels `authNoPriv` or `authPriv` (same as "-a _authProto_" for net-snmp).

### priv\_password: _privPassword_
The passphrase to use for SNMP v3 message encryption if security level is set to `authPriv` (same as "-x _privPassword_" for net-snmp).

### priv\_protocol: _privProto_
The protocol to use for SNMP v3 message encryption if security level is set to `authPriv` (same as "-X _privProto_" for net-snmp).

### context\_name: _ctxName_ # Has no default. -n option to NetSNMP.
If the SNMP v3 target device has 1+ context defined, use _ctxName_ to access it.


## lookups
Optional list of lookups to perform to mangle label names or values (deduced from index names) or even to drop a metric based on the final value of a label. Lookups get applied in same order they appear in the config file, before any overrides get applied. Note that leading and trailing whitespaces get removed automagically from label values, so one does not need to create extra rules to accomplish this.

### source\_indexes: _list_
The metric selector to which the lookup gets applied. Only if the related SNMP object (table) definition in the MIB contains *all* indexes named in the given _list_ the lookup gets applied to the metric (deduced from the walked objects). If more than one index is given, the index values of all indexes get append to the lookup label's OID and thus form the OID to lookup. E.g.:
```
      - source_indexes: [cmcIIIVarDeviceIndex, cmcIIIVarIndex]
        lookup: cmcIIIVarName
        rename: name
```
The OID of `cmcIIIVarName` is `1.3.6.1.4.1.2606.7.4.2.2.1.3` and if the value of the `cmcIIIVarDeviceIndex` is `123` and the value of `cmcIIIVarIndex` is `345` the would lookup `1.3.6.1.4.1.2606.7.4.2.2.1.3.123.345` to get the value for the label `cmcIIIVarName`, which gets finally renamed to `name`.

If `source_indexes` contains an empty list, and a lookup value is given, the lookup result gets inserted into the related metric as a new label. The label name is the same as the lookup name, the label value the lookup result. If the lookup value is a chain (i.e. it contains `|`), the value gets split into a list of lookup values, which finally get all inserted as labels into the metric. However, a possible `rename` and/or `revalue` option gets applied to the last lookup within the list, only. So if one needs to mangle all, one should configure a single lookup for each label. E.g.:
```
      - source_indexes: []
        mprefix: [cmcTcUnit1Status]
        lookup: cmcTcUnit1Text
        rename: name
```
This would create a metric like `cmcTcUnit1Status{name="RLCP"} 1` and without the lookup `cmcTcUnit1Status 1`.


### mprefix: _list_
An option to further narrow down, to which metrics this lookup definition gets applied. Only if a metric's name or OID starts with a string in the given _list_ the lookup gets applied to it. This gets handy if several objects use the same index, e.g. `entPhysicalIndex`, but depending on the name of the metric you wanna lookup its textual representation in the `shortNameTable` or `longNameTable`, or look it up in the `entPhysicalName` but rename the label to `fan` or `sensor` depending the name of the metric. The source\_indexes option would be to coarse for it, would produce different labels with the same value.

Per default the list is empty and implies no restriction wrt. the metric's name.

### drop\_source\_indexes: _boolVal_
If set to `true`, the labels deduced from source\_indexes and all intermediate labels are finally removed from the related metric. This avoids label clutter when the new index is unique.

### lookup: _tableNameChain_
Use the given _tableNameChain_ to lookup the value of the label. Usually this is just a single table entry name (e.g. `entPhysicalName`) - the source\_indexes name (e.g. entPhysicalIndex) gets used to map the index number to a textual aka human friendly representation. However, for some rare cases one needs an indirect lookup, to resolve the final value. In this case you name all "tables" in the required order separated by a single pipe symbol (`|`). A real world example for it is the CISCO-PROCESS-MIB:
```
cpmCPUTotalTable OBJECT-TYPE
    SYNTAX          SEQUENCE OF CpmCPUTotalEntry
    MAX-ACCESS      not-accessible
    STATUS          current
    DESCRIPTION     "A table of overall CPU statistics."
    ::= { cpmCPU 1 }

cpmCPUTotalEntry OBJECT-TYPE
    SYNTAX          CpmCPUTotalEntry
    MAX-ACCESS      not-accessible
    STATUS          current
    DESCRIPTION "Overall information about the CPU load. ..."
    INDEX           { cpmCPUTotalIndex }
    ::= { cpmCPUTotalTable 1 }

CpmCPUTotalEntry ::= SEQUENCE {
        cpmCPUTotalIndex                 Unsigned32,
        cpmCPUTotalPhysicalIndex         EntPhysicalIndexOrZero,
        cpmCPUTotal5sec                  Gauge32,
        ...
}
...
cpmCPUTotalPhysicalIndex OBJECT-TYPE
    SYNTAX          EntPhysicalIndexOrZero
    MAX-ACCESS      read-only
    STATUS          current
    DESCRIPTION     "The entPhysicalIndex of the physical entity ..."
    ::= { cpmCPUTotalEntry 2 }
...
```
So the `cpmCPUTotalIndex` needs to be used to obtain the `cpmCPUTotalPhysicalIndex` for the related entry, and this one can be used to determine the human readable name of the hardware e.g. via `entPhysicalName` table. The generator configuration snippet to accomplish that would look like this:
```
      - source_indexes: [cpmCPUTotalIndex]
        mprefix: [cpmCPU]
        lookup: cpmCPUTotalPhysicalIndex|entPhysicalName
```
NOTE: A lookup may overwrite any label already inserted. So if one has more than a single lookup, take care of its order.

### rename: _newIndexName_
Rename the label produced by the last component of the *lookup*._tableNameChain_ to _newIndexName_. Per default (i.e. if empty) it stays as is.

### revalue:
Change the value produced using the last component of the *lookup*._tableNameChain_. NOTE that if this option is used, a possibly "SNMP object not found" (e.g. if the entry for a given index doesn't exist anymore) results into an empty String to which the given regex gets applied.

#### regex: _regexExpr_
The regex to use. If it matches the final value, replace it with the expression of `value`. One may use capture-groups to keep/transfer certain parts to the value expression.

#### value: _newValue_
Replace the value of the related label with the given _newValue_ if _regexExpr_ matched the current value of the label. Capture-groups using `$num` are supported.

Special: If _newValue_ results into `@drop@`, the metric gets dropped. So in contrast to *overrides*._metricName_.*ignore*.*true* it allows one to drop a metric not by its name but by its label value(s). E.g. if one has an Switch with a lot of transceiver on is usually not really interested in voltage/current/temperature, but retrieving the whole table is much faster than retrieving the single entries one is interested in, one may use this feature to get rid off it immediately and thus saves the prometheus client a lot of work and energy of course.

A real world example showing such a case is:
```
    lookups: &entSensorValueTable_lookups
      - source_indexes: [entPhysicalIndex]
        mprefix: [entSensorValue]
        lookup: entPhysicalName
        rename: name
        revalue:
          regex: '.*Transceiver.*' # don't need Xcvr stats
          value: '@drop@'
        drop_source_indexes: true
```
which results only into 4 instead of 4\*4\*32+4=260 metrics:
```
snmp_entSensorValue{name="module-1 BACK"} 26
snmp_entSensorValue{name="module-1 CPU"} 35
snmp_entSensorValue{name="module-1 FRONT"} 21
snmp_entSensorValue{name="module-1 TH"} 42
snmp_entSensorValue{name="module-1 VRM-1"} 42
```

#### sub\_oids: _regexExpr_
If the specified _regexExpr_ does not match the related metric instance' subOid, the regex/value pair evaluation gets skipped and handled as 'no match'.

Wrt. the example above: if one retrieves the `entSensorValueTable` it contains the entries for `entSensorValue` (`1.3.6.1.4.1.9.9.91.1.1.1.1.4`), which results per default into a metric named `entSensorValue`, but many metric instances, because there are usually more than one. Those instances refer to the OID `1.3.6.1.4.1.9.9.91.1.1.1.1.4.`*${entPhysicalIndex}*, where the trailing part is the subOid (by default it gets injected as label named `entPhysicalIndex` having the value of the index). Usually it is a single number, however, in some rare cases wher the mib entry has defined more than one index, it can be more, e.g. `22.1`. So if one wants to drop the metrics for `Transceivers` having an entPhysicalIndex of 300054573..300054579 only, one could add `sub_oids: 30005457[3-9]` to the `revalue` entry.

NOTE: Usually (e.g. for enumerated hardware) indexes are stable, do not change.
However, for others like process lists they are definitely unstable. So make sure, that you have understood, what your SNMP server is doing, before using `sub_oids`.

### remap
This is an optional map, which allows one to replace label values. The final label value (i.e. after optional revalue settings got applied) is the key for the map. If the map contains it, the label value gets replaced by the value of the related map entry. Otherwise it stays at is. This might be more efficient than applying a list of regex to each metric value several times. However, take care to not run into `* collected metric ... was collected before with the same name and label values` by mapping several values to the same result which eventually make the metric non-unique anymore (and therefore the error).

## overrides
The `override` config deals with metric names and values. E.g. it allows one to drop metrics based on its value, change the metric's name, modify/remap the metric value, or to change its representation type (gauge, counter, etc.).

### _metricName_
The name of the metric to which this override should be applied.

#### type: _newType_
Set the type used to convert the received SNMP value (collection of one or more bytes) to the metric value string to _newType_. By default it gets deduced from the SNMP object's SYNTAX within the MIB. Allowed types are:
- *gauge*:  An integer with type gauge.
- *counter*: An integer with type counter.
- *OctetString*: A bit string, rendered as 0xff34.
- *DateAndTime*: An RFC 2579 DateAndTime byte sequence. If the device has no time zone data, UTC is used.
- *DisplayString*: An ASCII or UTF-8 string.
- *PhysAddress48*: A 48 bit MAC address, rendered as 00:01:02:03:04:ff.
- *Float*: A 32 bit floating-point value with type gauge.
- *Double*: A 64 bit floating-point value with type gauge.
- *InetAddressIPv4*: An IPv4 address, rendered as 1.2.3.4.
- *InetAddressIPv6*: An IPv6 address, rendered as 0102:0304:0506:0708:090A:0B0C:0D0E:0F10.
- *InetAddress*: An InetAddress per RFC 4001. Must be preceded by an InetAddressType.
- *InetAddressMissingSize*: An InetAddress that violates section 4.1 of RFC 4001 by not having the size in the index. Must be preceded by an InetAddressType.
- *EnumAsInfo*: An enum for which a single timeseries is created. Good for constant values.
- *EnumAsStateSet*: An enum with a time series per state. Good for variable low-cardinality enums.
- *Bits*: An RFC 2578 BITS construct, which produces a StateSet with a time series per bit.
- *uptime*: snmp-exporter internal. Converts the value (usually TimeTicks) into a boot time UNIX timestamp (i.e. seconds since 1970-01-01 00:00:00 UTC), so that it becomes a constant and can be stored in a very efficient way by time series DBs. However, this assumes, that scraping the related target takes always the same time +-2 s (snmp-exporter rounds it by 2), because the time gets calculated wrt. to the time when scraping has been done (snmp-exporter fetches all required SNMP data first, before it starts to process it).

#### ignore: _boolVal_
Drops the metric from the exporter's module config if set `true`. And of course: if no metric gets created, no lookups as well as no regex\_extracts have an impact on it. However, if needed, the required SNMP request will be made to obtain the required data, e.g. to resolve an index number of a table into its textual representation.

#### regex\_extracts:
Specifies how a new metric should be created. The generic format is:
```
MetricSuffix:             # Special: leading `.` or `^`
  - regex: regexExpr
    value: newValue       # Special: `@drop@`
    sub_oids: regexExpr   # optional subOid filter.
  ...
```
A new metric gets created, which inherits the name of the metric to which this override gets applied, but with the _MetricSuffix_ append. The exporter evaluates each regex/value pair one after another. On match the metric's value gets set to the evaluated regex - capture-groups are supported. If the obtained string can be parsed as float64, the metric gets returned having its value set to the parsed float. Otherwise a label having the same name as the metric itself and the value of the obtained string gets insterted into the metric. The value of the metric gets set to `1.0`.

So first match always wins and stops regex evaluation!

If all regex/value evals fail, the given _MetricSuffix_ would not emit a metric. Finally, after all _MetricSuffix_ configs have been processed, the original metric gets dropped.

If a `sub_oids` regex is given, it behaves like described in the lookup section: if it matches the subOid of the related metric, it gets applied as usual, otherwise it gets not applied and the result is set to "no match".

NOTE: Because regex\_extracts configs get **not applied** to metrics having its type set to *EnumAsInfo*, *EnumAsStateSet*, or *Bits*, one may need to set its type explicitly to somthing else, e.g. *DisplayString*.

NOTE: In contrast to the upstream version, a zero length result string does not cause a metric to be dropped anymore (use `@drop@` instead - see below).

Specials:

If the _MetricSuffix_ starts with a dot (`.`), the new metric name gets created by just replacing the dot with the module prefix + `_` (if any). If it starts with a circumflex (`^`), it gets removed and the remaining part becomes the new metric name (i.e. no prefix). Otherwise _MetricSuffix_ gets append to the related metric name.

If the _newValue_ results into `@drop@`, the original metric gets dropped and no new metric, no matter, whether previous regex pairs had a match. So to drop e.g. only metrics having a value of `0`, one may use:
```
unit1SensorSetHigh:
  type: 'DisplayString'
  regex_extracts:
    '':
      - regex: '0'
        value: '@drop@'
      - regex: '.*'
        value: '$1'
```
The 2nd regex pair is important, otherwise no match would happen for values != 0 and thus no new metric created (and the original gets dropped as usual).

#### remap
This optional setting allows one to replace a metric's value using a map (instead of a bunch of regex pairs). After the optional regex\_extracts got applied, the value gets converted into its string representation and used as key for the lookup within the map. On match the value of the entry found becomes the metric's value. However, for `counter`, `gauge`, `Float`, `Double`, `DateAndTime` and `EnumAs*` a new value gets parsed as Float64 first - only if convertion succeeds, the new value will be set (otherwise the metric value is kept as is). If the result of a map lookup is `@drop@` the related metric gets dropped. For `Bits` no remapping gets applied (create an issue on [github](https://github.com/jelmd/snmp_exporter/issues), if you really need it).


#### rename
This optional array contains sub\_oids/value pairs. If the `sub_oids` regex matches the subOid of the related metric instance, the metric's name gets set to `value`. First match wins. If no match occures, the metric name stays as is. E.g.
```
    overrides: &lcpIII_entPhySensorValue_overrides
      entPhySensorValue:
        rename:
          - value: lcp_fan_pct
            sub_oids: '3009|301[0-4]'
          - value: lcp_temperature_C
            sub_oids: ''100[18]|300[1-8]|301[56]'
```
This would cause all metric instances having a subOid of 3009..3014 to be renamed to `lcp_fan_pct`, and all instances with a subOid of 1001, 1008, 3001..3008, 3015, and 3016 to be renamed to `lcp_temperature_C`. All others will keep its name `entPhySensorValue`. But remember, the name can still be overwritten/modified by other directives like `regex_extracts`.


# EnumAsInfo and EnumAsStateSet

SNMP contains the concept of integer indexed enumerations (enums). There are two ways to represent these strings in Prometheus. They can be "info" metrics, or they can be "state sets". SNMP does not specify which should be used, and it's up to the use case of the data. Some users may also prefer the raw integer value, rather than the string. In order to set enum integer to string mapping, you must use one of the two overrides.

*EnumAsInfo* instructs the exporter to convert the obtained metric value into its text counterpart, inject a new label into the metric having the same name as the metric itself. The labels value gets set to the text found, the metrics value gets set to 1. It should be used for properties that provide inventory-like data. For example a device type, the name of a colour etc. It is important that this value is constant. E.g.:
```
ifOperStatus{ifIndex="83886080"} 2
# becomes
ifOperStatus{ifIndex="83886080", ifOperStatus="down"} 1
```

*EnumAsStateSet* instructs the exporter to do the same as for `EnumAsInfo`, but in addition to create a metric for each possible enum value with the metric value set to `0` and the label value set to the enum text. E.g. because
```
# snmptranslate -Pu -Tp -IR ifOperStatus
+-- -R-- EnumVal   ifOperStatus(8)
         Values: up(1), down(2), testing(3), unknown(4), dormant(5), notPresent(6), lowerLayerDown(7)
```
we would get seven instead of one metric for a single entry:
```
ifOperStatus{ifIndex="83886080"} 2
# becomes
ifOperStatus{ifIndex="83886080", ifOperStatus="down"} 1
ifOperStatus{ifIndex="83886080", ifOperStatus="up"} 0
ifOperStatus{ifIndex="83886080", ifOperStatus="testing"} 0
ifOperStatus{ifIndex="83886080", ifOperStatus="unknown"} 0
ifOperStatus{ifIndex="83886080", ifOperStatus="dormant"} 0
ifOperStatus{ifIndex="83886080", ifOperStatus="notPresent"} 0
ifOperStatus{ifIndex="83886080", ifOperStatus="lowerLayerDown"} 0
```
So *EnumAsStateSet* should be used for things that represent state or that you might want to alert on. For example the link state, is it up or down, is it in an error state, whether a panel is open or closed etc. Please be careful to not use this for high cardinality values as it will generate 1 time series per possible value.


# Where to get MIBs

Some of these are quite sluggish, so use wget to download.

Put the extracted mibs in a location NetSNMP can read them from. `$HOME/.snmp/mibs` is one option.

* Cisco: ftp://ftp.cisco.com/pub/mibs/v2/v2.tar.gz
* APC: https://download.schneider-electric.com/files?p_File_Name=powernet432.mib
* Servertech: ftp://ftp.servertech.com/Pub/SNMP/sentry3/Sentry3.mib
* Palo Alto PanOS 7.0 enterprise MIBs: https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/zip/technical-documentation/snmp-mib-modules/PAN-MIB-MODULES-7.0.zip
* Arista Networks: https://www.arista.com/assets/data/docs/MIBS/ARISTA-ENTITY-SENSOR-MIB.txt
                   https://www.arista.com/assets/data/docs/MIBS/ARISTA-SW-IP-FORWARDING-MIB.txt
                   https://www.arista.com/assets/data/docs/MIBS/ARISTA-SMI-MIB.txt
* Synology: https://global.download.synology.com/download/Document/Software/DeveloperGuide/Firmware/DSM/All/enu/Synology_MIB_File.zip
* MikroTik: http://download2.mikrotik.com/Mikrotik.mib
* UCD-SNMP-MIB (Net-SNMP): http://www.net-snmp.org/docs/mibs/UCD-SNMP-MIB.txt
* Ubiquiti Networks: http://dl.ubnt-ut.com/snmp/UBNT-MIB
                     http://dl.ubnt-ut.com/snmp/UBNT-UniFi-MIB
                     https://dl.ubnt.com/firmwares/airos-ubnt-mib/ubnt-mib.zip

https://github.com/librenms/librenms/tree/master/mibs can also be a good source of MIBs.

http://oidref.com is recommended for browsing MIBs.
