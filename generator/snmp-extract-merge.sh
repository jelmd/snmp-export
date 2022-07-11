#!/bin/ksh93

# A copy of https://github.com/jelmd/snakeyaml/releases/download/v1.30.20220624/snakeyaml-1.30.20220624.jar
SNAKEYML='/local/share/javax/snakeyaml.jar'

# no more changes
typeset -r VERSION='1.0' FPROG=${.sh.file} PROG=${FPROG##*/} SDIR=${FPROG%/*} \
	DEFAULT_OUT='snmp-extract.yml'

function showUsage {
	[[ -n $1 ]] && X='-?' ||  X='--man'
	getopts -a ${PROG} "${ print ${USAGE} ; }" OPT $X
}


function modules2file {
	typeset IN="$1" DSTDIR="$2" SFX="$3" LINE= C= N= F= IFS='\n'

	[[ -z ${SFX} ]] && SFX='mod'
	while read LINE ; do
		[[ ${LINE:0:8} == 'modules:' ]] && continue
		# output is stable: no comments and indent == 2 space chars
		if (( ${#LINE} == 0 )) || [[ ${LINE:3:1} == ' ' ]]; then
			C+="${LINE}\n"
			continue
		fi
		[[ -n $N && -n $C ]] && print "$C" >>${DSTDIR}/${N}.${SFX}
		C="${LINE}\n"
		N="${LINE%%:*}"
		N="${N##* }"
		N="${N//\//_}" # just in case
		print -u2 "Checking module $N ..."
		if [[ ! $N =~ ^[-._a-zA-Z0-9]+$ ]]; then
			print -u2 "WARNING: Module name '$N' in '${IN}' is not allowed."
			exit 99
		fi
	done<"${IN}"
	[[ -n $N ]] && print "$C" >>${DSTDIR}/${N}.${SFX}
}

function normalize {
	typeset -n FILES=$1
	typeset E F MODULE M DST="$2"
	integer L=${#TMPF} LA LB N=0 C=0

	(( L += 11 ))
	for F in "${FILES[@]}" ; do
		E="${TMPF}/modules.${F##*/}"
		java -jar ${SNAKEYML} $F |grep -v '^modules:' >"$E"
		if [[ ! -s $E ]]; then
			(( N == 0 )) && KEEP=0 || KEEP=1
			print -u2 "ERROR: fix file '$F' and try again."
			exit 98
		fi
		modules2file "$E" ${TMPF} 'mod'
		(( N++ ))
	done
	(( N == 0 )) && KEEP=0 && return 0
	print 'modules:' >${TMPF}/cfg
	cat ${TMPF}/modules.* >>${TMPF}/cfg
	# merge doubles
	java -jar ${SNAKEYML} ${TMPF}/cfg >"${DST}"

	# eliminate dups
	modules2file "${DST}" ${TMPF} 'mod2'
	for F in ${TMPF}/*.mod ; do
		E=${F}2
		M=${F##*/}
		if [[ ! -f $E ]]; then
			print -u2 "WARNING: module '${M%.mod}' vanished in final config."
			continue
		fi
		(( C++ ))
		A=( ${ ls -l $F ; } )
		B=( ${ ls -l $E ; } )
		LA=${A[4]}
		LB=${B[4]}
		(( N = LB - LA ))
		# Allow 1 byte diffs, which are usually just a '\n'
		if (( N != 0 && N != 1 )); then
			print -u2 "WARNING: module '${M%.mod}' differs ($N byte):"
			diff -u $F $E >&2
		fi
	done
	(( C == 0 )) && KEEP=0 && return 0
}

function cleanup {
	(( KEEP )) && \
		print "Keeping '${TMPF}' - remove when you are done." && return 0
	[[ -n ${TMPF} && -d ${TMPF} ]] &&  rm -rf ${TMPF}
}

function doMain {
	typeset -a FILES F T P
	[[ -z $1 ]] && FILES=( "${SDIR}" ) || FILES=( "$@" )
	for P in "${FILES[@]}" ; do
		if [[ -d $P ]]; then
			for T in ~(N)$P/generator.*.yml; do
				[[ ${T##*/} == 'generator.default.yml' ]] && continue
				[[ -f $T && -s $T ]] && F+=( "$T" )
			done
			continue
		fi
		[[ ! -f $P ]] && \
			print -u2 "WARNING: Invalid path '$P' ignored." && continue
		[[ -s $P ]] && F+=( "$P" )
	done
	[[ -z $F ]] && KEEP=0 && return 0
	[[ -z ${OUT} ]] && OUT="${DEFAULT_OUT}"
	normalize F ${TMPF}/cfg.yml
	snmp-export-cfg generate -f ${TMPF}/cfg.yml -o "${OUT}"
	print -u2 'Done:'
	ls -l "${OUT}" >&2
}


USAGE="[-?${VERSION}"' ]
[-copyright?Copyright (c) 2022 Jens Elkner. All rights reserved.]
[-license?CDDL 1.0]
[+NAME?'"${PROG}"' - merge multiple snmp-export config files.]
[+DESCRIPTION?This little helper script generates a snmp-export config file from all given files \apath\a and all \agenerator.*.yml\a files in the given directories \apath\a, or if neither a file nor a directory was given, from the directory containing this script. Note: For convenience any \bgenerator.default.yml\b gets skipped unless explicitly given.]
[+?Each file is expected to contain a single `modules:` section, only. Snakeyaml gets used to normalize all configs one-by-one (i.e. resolve and remove all anchors and references including comments) and finally \bsnmp-export\b to create the final config file (see option \b-o ...\b).]
[h:help?Print this help and exit.]
[F:functions?Print a list of all functions available.]
[T:trace]:[functionList?A comma separated list of functions of this script to trace (convinience for troubleshooting).] 
[+?]
[k:keep?Keep the temporary directory used for processing files.]
[o:out]:[path?Where to store the generated config finally. Default: \b'"${DEFAULT_OUT}"'\b]
\n\n
[\apath\a]...
'

X="${ print ${USAGE} ; }"
unset KEEP ; integer KEEP=0
while getopts "${X}" OPT ; do
	case ${OPT} in
		h) showUsage ; exit 0 ;;
		T)	if [[ ${OPTARG} == 'ALL' ]]; then
				typeset -ft ${ typeset +f ; }
			else
				typeset -ft ${OPTARG//,/ }
			fi
			;;
		F) typeset +f && exit 0 ;;
		k) KEEP=1 ;;
		o) OUT="${OPTARG}" ;;
		*) showUsage 1 ; exit 1 ;;
	esac
done

X=$((OPTIND-1))
shift $X && OPTIND=1
unset X

TMPF=${ mktemp -d -t generator.XXXXXX.yml; }
[[ -z ${TMPF} ]] && print -u2 "Unable to create tempfile - exiting." && exit 1

trap cleanup EXIT

doMain "$@"
