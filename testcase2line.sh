#!/bin/ksh93

SDIR=${.sh.file%/*}
FILE='collector_test.go'
TEST_SRC=${SDIR}/${FILE}
integer N=-1 C K=-1
TESTS=( 'TestPduToSample' 'TestIndexesToLabels' )
X='============================================================================'

print "${FILE}\n${X:0:${#FILE}}\nCase# Line#\n"

while read -A L ; do
	(( N++ ))
	if [[ $L == 'func' ]]; then
		[[ ${L[1]:0:${#TESTS[K+1]}} == ${TESTS[K+1]} ]] && { C=0; (( K++ )); print ${TESTS[K]}; }
		continue
	fi
	(( K < 0 )) && continue
	if (( K == 0 )); then
		if [[ $L == 'pdu:' && ${L[1]} == '&gosnmp.SnmpPDU{' ]]; then
			printf "%-3d  %4d\n" C N 
			(( C++ ))
		fi
	elif (( K == 1 )); then
		if [[ $L == 'oid:' && ${L[1]:0:6} == '[]int{' ]]; then
			printf "%-3d  %4d\n" C N
			(( C++ ))
		fi
	fi
done<${TEST_SRC}
