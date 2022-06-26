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
      - OID                                #   (both with brace expansion)
      - snmpObjectName
      ...
    version: snmpVersion                   # 1..3. Default: 2 (i.e. SNMPv2c)
    max_repetitions: intNumber             # Default: 25
    retries: intNumber                     # Default: 3
    timeout: numSeconds                    # Default: 5
    prefix: metricsPrefix                  # Default: ''
    fallback_label: labelName              # Optional.

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
        mprefix:                           #   Optional with one or more:
          - indexNamePrefix                #   (prefix '_' => regex, otherwise
          - indexOIDPrefix                 #    brace expansion)
          ...
        lookup: tableNameChain             #   Mandatory (may use matched groups if mprefix is a regex).
                                           #   (Special: '_idx' - auto indexing)
        sub_oids: regexExpr                #   Optional subOid filter.
        drop_source_indexes: boolVal       #   Default: false
        rename: newIndexName               #   Default: '' (i.e. do not rename)
        revalue:                           #   Optional.
          regex: regexExpr                 #     Default: ''
          invert: boolVal                  #     Default: false
          value: newValue                  #     Default: '$1'. Special: '@drop@' .. drop metric on match.
          sub_oids: regexExpr              #     optional subOid filter.
        remap:                             #   Optional with one or more:
          key: val                         #   (Special: '@drop@' as above).
          ...
        sub_oid_remap:                     #   Optional with one or more:
          key: val                         #   (Special: '@drop@' as above).
          ...

    overrides:                             # Optional with one or more:
      metricNameList:                      #   Mandatory (brace expansion).
        ignore: boolVal                    #     Default: false
        type: newType                      #     Default: '' (i.e. keep type as is)
        fallback_label: labelName          #     Optional.
        regex_extracts:                    #     Optional with one or more:
          newSuffix:                       #       Default: '' (Special: leading `.` or `^`) with one or more:
            -  regex: regexExpr            #         Default: ''
               invert: boolVal             #         Default: false
               value: newValue             #         Default: '$1'. Special: '@drop@' .. drop metric on match.
               sub_oids: regexExpr         #         optional subOid filter.
            ...
        remap:                             #     Optional with one or more:
          key: val                         #     (Special: '@drop@' as above).
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

## brace expansion
To make it easier to specify source or targets and to avoid a lot of duplications, this generator supports brace expansions, when explicitly mentioned.

If `l1`,`l2` are either all lower case or all upper case letters in C locale,
`n1`,`n2`,`n3` signed numbers, s, s1, ... normal strings (literals), and
`fmt` a string specified as in [fmt.Printf()](https://pkg.go.dev/fmt#hdr-Printing) the
following expressions are recognized and expanded as described below:
- (1) `{s[,s1]...}`
- (2) `{l1..l2[..n3][%fmt]}`
- (3) `{n1..n2[..n3][%fmt]}`

The curly braces, dots and percent sign are literals, the brackets mark an
optional part of the brace expression - need to be ommitted.

They may appear anywhere in a string or a list of strings separated by a broken bar symbol (`¦`).

In the first form the generator iterates over the comma separated list of
strings and creates for each member a new string by replacing the brace
expression with the member.
E.g. `foo{bar,sel,l}` becomes `foobar¦foosel¦fool`.

In the second and third form the generator iterates from `l1` through `l2`
or `n1` through `n2` using the given step width `n3`. If `n3` is not given, it
gets set to `1` or `-1` depending on the first and second argument. If `%fmt`
is given, it will be used to create the string from the generated character
or number. Otherwise `%c` (2nd form) or `%d`(3rd form) will be used.

Finally a new list of strings gets generated, where the brace expression
gets replaced by the members of the one-letter or number list one-by-one.
E.g. `chapter{A..F}.1` becomes
`chapterA.1¦chapterB.1¦chapterC.1¦chapterD.1¦chapterE.1¦chapterF.1`,
and `{a,z}{1..5..3%02d}{b..c}x` expands to 2x2x2 == 8 strings:
`a01bx¦a01cx¦a04bx¦a04cx¦z01bx¦z01cx¦z04bx¦z04cx`.

One may escape curly braces with a backslash(`\`) to get it ignored, but since they are not
allowed in metric names, it doesn't make much sense for the generator case.
Any brace expression which cannot be parsed or uses invalid arguments gets
handled as literal without the enclosing curly braces. Note that in the
2nd form ASCII letters in the range of `a-z` and `A-Z` are accepted, only.



## modules
Just the anchor for all modules. The simplest module is just a name and a set of OIDs to walk.

## _moduleName_
The name of a module, the smallest "addressable" unit for a prometheus client.

## walk: _list_
List of OIDs and SNMP object names to walk via SNMP. NOTE that object names might be not unique within a MIB and therefore the generated config might not query the intended objects. If unsure, use OIDs instead. Basically if you do a something like `snmpbulkwalk -v 2c -c public -Pu -Pw -OX $targetIP $OID_or_Name` the object name shown after the double colon (`::`) becomes the name of the metric. If the related "table entry" (if any) has an `INDEX` definition all these indexes become the labels of the metric with the obtained index value set.

The generator deduces from the MIB, whether it needs to issue a `snmpget` (scalar object) or a `snmpbulkwalk` (tables and sub-trees). However, if the MIB definition is buggy (like HP's futuresmart3 MIB), the decision migth be wrong, because the scalar is not really a scalar, but has undeclared children (see `lookup` description for a detailed example). In this case one may prefix the OID or object name with a circumflex symbol (`^`). This instructs the generator to put the object into the bulkwalk section of the generated exporter config file.

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

## fallback\_label: _labelName _
Per default the exporter generates and injects a label for non-numeric metric values having the same name as the metric and using the metric's value as label value. E.g. the SNMP entry for `sysName` gets formatted as `sysName(sysName="foobar") 1`. Technically this approach causes probably no collision with other SNMP object names, however, the output becomes less readable (especially for long names) and might be hard to handle in a generic way and consume more resources for processing as needed.

When this optional property gets set, e.g. to `fallback_label: val` here at the module level, the exporter will now use `val` as metric label value instead of the metric name for all metrics when needed. Wrt. to the example mentioned before it would now look like this `sysName(val="foobar") 1`. If this is to coarse grained for you, you may set it in the `overrides` section for the intended metrics, too. The letter takes precedence over the module setting.


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


Basically the exporter iterates for each metric through all lookups in the same order as configured. First all indexes defined in the MIB for the related table (if any) get add as labels to the metric as *indexName*="*indexValue*". Than the values of the `source_indexes` (which are usually the same as the ones defined in the MIB) get joined using a dot (`.`) and form the subOid to use for the 1st `lookup`. If no entry exists with the desired OID or a `sub_oids` is given and does not match the related regex, the exporter does nothing and continues with the next lookup (if any). Otherwise it applies the `revalue` config if appropriate, the `remap` and finally the `sub_oid_remap` config (if any). If at the end of this cycle the resulting string is not empty (i.e. has at least 1 character), a new label *lookup*="*result*" gets injected into the metric instance (if the result is `@drop@` lookup stops immediately and the metric instance gets dropped). Otherwise, the *lookup* label gets removed. Therefore the order of lookups is important, one lookup may overwrite another, or even remove it. When all lookups are done, the `source_indexes` labels get removed from the metric if `drop_source_indexes == true` and the exporter continues with applying `overrides`.

So remember, every single lookup either inserts or removes a label (key=value pair), whereby an insert overwrites an existing label if it has the same key.


### source\_indexes: _list_
The metric selector to which the lookup gets applied. Only if the related SNMP object (table) definition in the MIB contains *all* indexes named in the given _list_ the lookup gets applied to the metric (deduced from the walked objects). If more than one index is given, the index values of all indexes get append to the lookup label's OID and thus form the OID to lookup. E.g.:
```
      - source_indexes: [cmcIIIVarDeviceIndex, cmcIIIVarIndex]
        lookup: cmcIIIVarName
        rename: name
```
The OID of `cmcIIIVarName` is `1.3.6.1.4.1.2606.7.4.2.2.1.3`. If the value of the `cmcIIIVarDeviceIndex` is `123` and the value of `cmcIIIVarIndex` is `345` the exporter would lookup `1.3.6.1.4.1.2606.7.4.2.2.1.3.123.345` to get the value for the label `cmcIIIVarName`, which gets finally renamed to `name`.

If `source_indexes` contains an empty list, and a lookup value is given, the lookup result gets inserted into the related metric as a new label. The label name is the same as the lookup name, the label value the lookup result. If the lookup value is a chain (i.e. it contains `¦`), the value gets split into a list of lookup names, which finally get all inserted as labels into the metric. However, a possible `rename` and/or `revalue` option gets applied to the last lookup within the list, only. So if one needs to mangle all, one should configure a single lookup for each label. E.g.:
```
      - source_indexes: []
        mprefix: [cmcTcUnit1Status]
        lookup: cmcTcUnit1Text
        rename: name
```
This would create a metric like `cmcTcUnit1Status{name="RLCP"} 1` and without the lookup `cmcTcUnit1Status 1`.


### sub\_oids: _regex_
Another option to further narrow down, to which metrics this lookup definition gets applied. If the *subOID* of the metric instance alias SNMP object does not match _regex_ the exporter skips this lookup and continues with the next one. For more details wrt. *subOID*  have a look at the `revalue` section below.

### drop\_source\_indexes: _boolVal_
If set to `true`, the labels deduced from source\_indexes and all intermediate labels are finally removed from the related metric. This avoids label clutter when the new index is unique.

### lookup: _tableNameChain_
Use the given _tableNameChain_ to lookup the value of the label. Usually this is just a single table entry name (e.g. `entPhysicalName`) - the source\_indexes name (e.g. entPhysicalIndex) gets used to map the index number to a textual aka human friendly representation. However, for some rare cases one needs an indirect lookup, to resolve the final value. In this case you name all "tables" in the required order separated by a single broken bar (`¦`). A real world example for it is the CISCO-PROCESS-MIB:
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
        lookup: cpmCPUTotalPhysicalIndex¦entPhysicalName
```

Since version 2.0.0 `lookup: _idx` is a special, which allows one e.g. to handle bogus or incomplete MIB defined object. E.g. HP defines an object named consumable-status-usage-units as a scalar, i.e. it is neither a table nor does are any children definied for this node. However, if one queries this object, an error occurs. E.g.:
```
admin> snmptranslate -Pu -Td -On -IR consumable-status-usage-units
.1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.10.1.1.17
consumable-status-usage-units OBJECT-TYPE
  -- FROM	FUTURESMART3a-MIB
  SYNTAX	INTEGER {ePixels(1), eTenthsOfGrams(2), eGrams(3), eRotations(4), ePages(5), eImpressions(6), ePercentLifeRemaining(7), eOther(8)} 
  MAX-ACCESS	read-only
  STATUS	optional
  DESCRIPTION	"This object is used to report the units used to measure the	
                capacity of this consumable.
                Additional information:
                This object will only exist on engines that are E-Label
                capable, but will exist on these engines regardless of 
                the cartridge being Authentic HP or NonHP.  This object 
                can be used to ensure the capability of the E-Label 
                feature for a given engine."
::= { iso(1) org(3) dod(6) internet(1) private(4) enterprises(1) hp(11) nm(2) hpsystem(3) net-peripheral(9) netdm(4) dm(2) device(1) destination-subsystem(4) print-engine(1) consumables(10) consumables-1(1) consumable-status(1) 17 }

admin> snmpget -c public -v2c -Pu -On $PRINTER consumable-status-usage-units
.1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.10.1.1.17 = No Such Instance currently exists at this OID

admin> snmpbulkwalk -c public -v2c -Pu -On $PRINTER consumable-status-usage-units
.1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.10.1.1.17.1.0 = INTEGER: ePercentLifeRemaining(7)
.1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.10.1.1.17.2.0 = INTEGER: ePercentLifeRemaining(7)
.1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.10.1.1.17.3.0 = INTEGER: ePercentLifeRemaining(7)
.1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.10.1.1.17.4.0 = INTEGER: ePercentLifeRemaining(7)

admin> snmpbulkwalk -c public -v2c -Pu -OX rubens consumable-status-usage-units
FUTURESMART3a-MIB::consumable-status-usage-units.1.0 = INTEGER: ePercentLifeRemaining(7)
FUTURESMART3a-MIB::consumable-status-usage-units.2.0 = INTEGER: ePercentLifeRemaining(7)
FUTURESMART3a-MIB::consumable-status-usage-units.3.0 = INTEGER: ePercentLifeRemaining(7)
FUTURESMART3a-MIB::consumable-status-usage-units.4.0 = INTEGER: ePercentLifeRemaining(7)
```

As you can see, the scalar has sub-entries and thus is not a scalar as defined in the MIB. Anyway, because the generator/exporter cannot deduce this from the buggy MIB, it creates a metric with the same name and value for each object (`consumable_status_usage_units 2`), which finally causes an 'same metric with same labels already inserted' error. To fix it, one may use `lookup: _idx`. In this case the exporter cuts off the OID of the metric from the OID of the instance (e.g. .1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.10.1.1.17.2.0 - .1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.10.1.1.17. = 2.0) and cuts off the trailing `.0` if any. So in this case the label `_idx="2"` gets inserted into the metric and finally makes all instances unique (`consumable_status_usage_units(_idx="2") 7`). A second use case is: If the metric OID is the same as the instance OID, the exporter cuts off the last two numbers of the OID and uses this as result instead - like row.column for a table.

Of course on may rename `_idx` to somthing else using the `rename` feature, or `remap` or transfom the value per `revalue` feature.

NOTE: If one uses more than a single lookups entry, the order of the items are important, because a lookups key:value result overwrites the label with the same name (key) if it already got inserted.

### mprefix: _list_
An option to further narrow down, to which metrics this lookup definition gets applied. Only if a metric's name or OID starts with a string in the given _list_ the lookup gets applied to it. This gets handy if several objects use the same index, e.g. `entPhysicalIndex`, but depending on the name of the metric you wanna lookup its textual representation in the `shortNameTable` or `longNameTable`, or look it up in the `entPhysicalName` but rename the label to `fan` or `sensor` depending the name of the metric. The source\_indexes option would be to coarse for it, would produce different labels with the same value.

List items are separated by a broken bar (`¦`) and per default subject to brace expansions. But if a list item has an underline (`_`) prefix, the item gets handled as a regex, which gets matched against potential metrics. One may use captured groups to modify the correponding lookup to use. E.g.:
```
modules:
  test:
    walk:
      - media{1..41}-page-count
    lookups:
      - source_indexes: []
        lookup: 'media$1-name'
        mprefix: ['_media([0-9]+)-page-count']
        rename: name
    overrides:
      media{1..41}-page-count:
        rename:
          - value: media_page_count
            sub_oids: '.*'
```
This little snippet would e.g. format `FUTURESMART3a-MIB::media1-page-count.0 = INTEGER: 10` as `media_page_count(name="A4") 10` if the result of the `media1-name` lookup is `A4`. 

Per default the mprefix list is empty and implies no restriction wrt. the metric's name.

### rename: _newIndexName_
Rename the label produced by the last component of the *lookup*._tableNameChain_ to _newIndexName_. Per default (i.e. if empty) it stays as is.

### revalue:
Change the value produced using the last component of the *lookup*._tableNameChain_. NOTE that if this option is used, a possibly "SNMP object not found" (e.g. if the entry for a given index doesn't exist anymore) results into an empty String to which the given regex gets applied.

#### regex: _regexExpr_
The regex to use. If it matches the final value, replace it with the expression of `value`. One may use capture-groups to keep/transfer certain parts to the value expression.

#### invert: _boolVal_
Negate the outcome of the regex match. I.e. if `invert` is `false` (the default), the exporter behaves as usual. However, if `invert` is set to `true`, the given `value` gets set only if no match occures.

#### value: _newValue_
Replace the value of the related label with the given _newValue_ if _regexExpr_ matched the current value of the label. Capture-groups using `$num` are supported.

Special: If _newValue_ results into `@drop@`, the metric gets dropped. So in contrast to *overrides*._metricNameList_.*ignore*.*true* it allows one to drop a metric not by its name but by its label value(s). E.g. if one has an Switch with a lot of transceiver on is usually not really interested in voltage/current/temperature, but retrieving the whole table is much faster than retrieving the single entries one is interested in, one may use this feature to get rid off it immediately and thus saves the prometheus client a lot of work and energy of course.

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
This is an optional map, which allows one to replace label values. The label value, after the optional revalue setting got applied, is the key for the map. If the map contains it, the label value gets replaced by the value of the related map entry. Otherwise it stays at is. This might be more efficient than applying a list of regex to each metric value several times. However, take care to not run into `* collected metric ... was collected before with the same name and label values` by mapping several values to the same result which eventually make the metric non-unique anymore (and therefore the error).

### sub\_oid\_remap
This is the same as `remap`, but the lookup key gets formed by the *subOid* of the related SNMP object and the label value produced so far, concatenated with a semicolon (`;`). E.g. `Temperature.Value` becomes `123;Temperature.Value` if `123` is the subOid of the related SNMP object.


## overrides
The `override` config deals with metric names and values. E.g. it allows one to drop metrics based on its value, change the metric's name, modify/remap the metric value, or to change its representation type (gauge, counter, etc.).

### _metricNameList_
The names of the metrics aka SNMP object seprated by a vertical broken bar (i`¦`) symbol to which this override should be applied. It is not possible to use wildcards here. However, since version 1.1. you may use brace expansions as described above, which will help a lot when dealing e.g. with HP printers.

NOTE: It is recommended to always use the SNMP object name and not the metric name, where all non-alphanumeric charcaters of the object name automatically get replaced by an underscore (`_`). If you get a message containing `SNMP object not found` this might be one reason for it.

#### type: _newType_
Set the type used to convert the received SNMP value (collection of one or more bytes) to the metric value string to _newType_. By default it gets deduced from the SNMP object's SYNTAX within the MIB. Allowed types are:
- *gauge*:  An integer with type gauge.
- *counter*: An integer with type counter.
- *OctetString*: A byte sequence, rendered as hex values, e.g. 0xff34.
- *DateAndTime*: An RFC 2579 DateAndTime byte sequence. If the device has no time zone data, UTC is used. In addition two similar formats are supported: 5 byte as ymdHM and 7 byte as ymduHMS (usally used by HP printers).
- *DisplayString*: An ASCII or UTF-8 string. Note that any non-UTF-8 byte gets converted into the UTF-8 sequence hand sign (✋= 0xe2 0x9c 0x8b).
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

#### fallback\_label: _labelName _
This has the same effect as `fallback_label: labelName` in the module setting, but gets used for the metrics specified in the _metricNameList_ if needed, only.  It takes precedence of the module setting with the same name (if any). For more details read the `fallback_label` decription in the module section.

#### ignore: _boolVal_
Drops the metric from the exporter's module config if set to `true`. And of course: if no metric gets created, no lookups as well as no regex\_extracts have an impact on it. However, if needed, the required SNMP request will be made to obtain the required data, e.g. to resolve an index number of a table into its textual representation.

#### regex\_extracts:
Specifies how a new metric should be created. The generic format is:
```
MetricSuffix:             # Special: leading `.` or `^`
  - regex: regexExpr
    invert: boolVal       # Default: false
    value: newValue       # Special: `@drop@`
    sub_oids: regexExpr   # optional subOid filter.
  ...
```
Per default on match a new metric gets created, which inherits the name of the metric to which this override gets applied, but with the _MetricSuffix_ append. The exporter evaluates each regex/value pair one after another. On match the metric's value gets set to the expanded `newValue` (capture-groups are supported). If `invert` is set to `true`, the value gets replaced with the `newValue` only if no match occures. If the obtained string can be parsed as float64, the metric gets returned having its value set to the parsed float. Otherwise a label having the same name as the metric itself and the value of the obtained string gets insterted into the metric. The value of the metric gets set to `1.0`.

First match always wins and stops regex evaluation of the `regex_extracts` item!

If all regex/value evals fail, the given _MetricSuffix_ would not emit a metric. Finally, after all _MetricSuffix_ configs have been processed, the original metric gets dropped. This is very important! So if you miss a metric, you possibly managed to get it chomped by not providing a final match like `(.*)` with `$1`.

If a `sub_oids` regex is given, it behaves like described in the lookup section: if it matches the subOid of the related metric, it gets applied as usual, otherwise it gets not applied and the result is set to "no match".

NOTE: Because regex\_extracts configs get **not applied** to metrics having its type set to *EnumAsInfo*, *EnumAsStateSet*, or *Bits*, one may need to set its type explicitly to somthing else, e.g. *DisplayString*.

NOTE: In contrast to the upstream version, a zero length result string does not cause a metric to be dropped anymore (use `@drop@` instead - see below).

Specials:

If the _MetricSuffix_ starts with a dot (`.`), the new metric name gets created by just replacing the dot with the module prefix + `_` (if any). If it starts with a circumflex (`^`), the part after the circumflex becomes the new metric name (i.e. no prefix). Otherwise _MetricSuffix_ gets append to the related metric name.

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
Again, the 2nd regex pair is important, otherwise no match would happen for values != 0 and thus no new metric created (and the original gets dropped as usual).

#### remap
This optional setting allows one to replace a metric's value using a map (instead of a bunch of regex pairs). After the optional regex\_extracts got applied, the value gets converted into its string representation and used as key for the lookup within the map. On match the value of the entry found becomes the metric's value. However, for `counter`, `gauge`, `Float`, `Double`, `DateAndTime` and `EnumAs*` a new value gets parsed as Float64 first - only if convertion succeeds, the new value will be set (otherwise the metric value is kept as is). If the result of a map lookup is `@drop@` the related metric gets dropped. For `Bits` no remapping gets applied (create an issue on [github](https://github.com/jelmd/snmp-export/issues), if you really need it).


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

## HINTS

If the result of a metric is not a number, a new label with the same name as the metric gets injected into the metric, with its value set to the result, and the metrics value set to `1.0`. This happens at the very last step and thus there is no direct way to rename the injected label. However, what one may do is to inject a new label with the intended name using a `lookups` item with an empty source\_indexes list, a lookup entry for this metric and rename it to the intended name. So the last thing one needs than to do is to avoid the automatic insertion of the label. For this one may use an overrides entry for the metric having a `regex_extracts` entry, which replaces `.*` with `1`.

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

# Examples

This repository contains the following generator files:
- [generator.yml](./generator.yml): Misc targets maintained by the upstream (not recommended for production).
- [generator.apc.yml](./generator.apc.yml): tuned for our APC UPS SURTXLI 8 and 10Ks as well as APC Automatic Transfer Switches (ATS).
- [generator.cisco.yml](./generator.cisco.yml) tuned for the Cisco switches (basically 3560 \* and Nexus 3000 switches like C3232C) we use.
- [generator.rittal.yml](./generator.rittal.yml) tuned for Rittal's managed PDUs and Liquid Cooling Packages (old CMC II driven alias lcpII and recent CMC III driven alias lcpIIIa and depending on the current config lcpIIIb\_V3 and lcpIIIb\_V4).

For easier testing and adjustments we use in the latter 3 files YAML features like anchors and aliases because this crap does not support multi-line comments and is a pure maintenance nightmare. To use them a [modified version of snakeyaml](https://github.com/jelmd/snakeyaml) is needed to translate it to a YAML spec compatible file before we can feed it into the generator. However, there is probably not a single correct, bug free YAML implementation in this world and thus snakeyaml has its own problems and this + the required modifications we need sometimes lead to confusing results. So the best thing one can do is simply use a better preprocessor or none at all, or maintain your configuration as a json formatted file, which will work for both, the generator as well as the exporter.


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
