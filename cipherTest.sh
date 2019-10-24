#!/usr/bin/env bash

set -e

control_c() {
	[ -t 1 ] && echo "\r\e[K"
	exit 1
}

debug() {
	[ "${DEBUG:-0}" -gt 0 ] && printf "\ndebug: $*\n" >&2
	return 0
}

trap control_c SIGINT

if [ "z$1" = "z" -o "z$2" = "z" ]
then
	echo "Usage: $0 <hostname> <port>" >&2
	echo "	Behavior is undefined if hostname is invalid or not listening on the port." >&2
	echo "	Credits: Patrick Bogen <pdbogen@cernu.us>" >&2
	exit 2
fi

HOST=$1
if echo $HOST | grep -qE '^([0-9]+\.){3}[0-9]+$'
then
	IP=$1
else
	IP=`host $HOST | awk '/^[[:alnum:].-]+ has address/ { print $4 }'`
fi
PORT=$2

declare -a CIPHERS
declare -a PROTOS
declare -a MACS
declare -a KX
declare -a v2_ciphers

request='HEAD / HTTP/1.1\r\nHost: '"$HOST"'\r\nConnection: close\r\n\r\n'

CIPHERS=(`gnutls-cli -l | grep Ciphers: | cut -d' ' -f2- | tr -d ','`)
debug "Our supported ciphers: ${CIPHERS[*]}"

PROTOS=(`gnutls-cli -l | grep Protocols: | cut -d' ' -f2- | tr -d ','`)
debug "Our supported protocols: ${PROTOS[*]}"

MACS=(`gnutls-cli -l | grep MACs: | cut -d' ' -f2- | tr -d ','`)
debug "Our supported MACs: ${MACS[*]}"

KX=(`gnutls-cli -l | grep "^Key exchange algorithms" | cut -d' ' -f 4- | tr -d ','`)
debug "Our supported KX: ${KX[*]}"

if gnutls-cli -l | grep -q '^Elliptic curves'; then
	CURVES=(`gnutls-cli -l | grep '^Elliptic curves' | cut -d' ' -f 3- | tr -d ','`)
	debug "Our supported curves: ${CURVES[*]}"
	all_curves="+CURVE-ALL"
elif gnutls-cli -l | grep -q '^Groups'; then
	CURVES=(`gnutls-cli -l | grep '^Groups' | cut -d' ' -f 2- | tr -d ','`)
	debug "Our supported groups: ${GROUPS[*]}"
	all_curves="+GROUP-ALL"
fi

PKSIGS=(`gnutls-cli -l | grep '^PK-signatures:' | cut -d' ' -f 2- | tr -d ','`)
debug "Our supported signature algorithms: ${PKSIGS[*]}"

v2_ciphers=(`openssl ciphers -ssl2 | tr ':' ' '`)

# for i in ${PROTOS[@]}; do all_protos="${all_protos:+$all_protos:}+$i"; done
# for i in ${CIPHERS[@]}; do all_ciphers="${all_ciphers:+$all_ciphers:}+$i"; done
# for i in ${MACS[@]}; do all_macs="${all_macs:+$all_macs:}+$i"; done
# for i in ${KX[@]}; do all_kx="${all_kx:+$all_kx:}+$i"; done
# for i in ${CURVES[@]}; do all_curves="${all_curves:+$all_curves:}+$i"; done
# for i in ${PKSIGS[@]}; do all_pksigs="${all_pksigs:+$all_pksigs:}+$i"; done

all_protos="+VERS-ALL"
all_ciphers="+CIPHER-ALL"
all_macs="+MAC-ALL"
all_kx="+KX-ALL"
all_pksigs="+SIGN-ALL"

cur=0
total=$(( ${#CIPHERS[@]} + ${#PROTOS[@]} + ${#MACS[@]} + ${#KX[@]} + ${#CURVES[@]} + ${#PKSIGS[@]} ))

if echo -ne $request | gnutls-cli --insecure --priority NONE:+CTYPE-X.509:$all_protos:$all_kx:$all_macs:+COMP-NULL:$all_ciphers:$all_curves:$all_pksigs -p $PORT $IP >/dev/null 2>&1; then
	true
else
	echo -ne $result | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:$all_ciphers:$all_curves:$all_pksigs -p $PORT $IP
	exit 1
fi

# Test each protocol promiscuously and remove any that will never work
result=""
for tgt in ${PROTOS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:+$tgt:$all_kx:$all_macs:+COMP-NULL:$all_ciphers:$all_curves:$all_pksigs -p $PORT $IP > /dev/null 2>&1
	then
		debug "proto $tgt is usable"
		[ -z "$result" ] && result="$tgt" || result="$result $tgt"
	fi
done

PROTOS=( $result )
for i in ${PROTOS[@]}; do all_protos="${all_protos:+$all_protos:}+$i"; done

# Test each cipher promiscuously and remove any that will never work
result=""
for cipher in ${CIPHERS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority "NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:+$cipher:$all_curves:$all_pksigs" -p $PORT $IP > /dev/null 2>&1
	then
		debug "cipher $cipher is usable"
		[ -z "$result" ] && result="$cipher" || result="$result $cipher"
	fi
done
CIPHERS=( $result )
result=""
for i in ${CIPHERS[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_ciphers=$result

# Test each MAC promiscuously and remove any that will never work
result=""
for tgt in ${MACS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:+$tgt:+COMP-NULL:$all_ciphers:$all_curves:$all_pksigs -p $PORT $IP > /dev/null 2>&1
	then
		debug "MAC $tgt is usable"
		[ -z "$result" ] && result="$tgt" || result="$result $tgt"
	fi
done
MACS=( $result )
result=""
for i in ${MACS[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_macs=$result

# Test each KX promiscuously and remove any that will never work
result=""
for tgt in ${KX[@]}
do
	if echo "$tgt" | grep -q PSK; then
		debug "skipping PSK KX $tgt"
		continue
	fi

	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:+$tgt:$all_macs:+COMP-NULL:$all_ciphers:$all_curves:$all_pksigs -p $PORT $IP > /dev/null 2>&1
	then
		debug "KX $tgt is usable"
		[ -z "$result" ] && result="$tgt" || result="$result $tgt"
	fi
done
KX=( $result )
result=""
for i in ${KX[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_kx=$result

# Test each curve promiscuously and remove any that will never work
result=""
for tgt in ${CURVES[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:$all_ciphers:+$tgt:$all_pksigs -p $PORT $IP > /dev/null 2>&1
	then
		debug "curve $tgt is usable"
		result="${result:+$result }$tgt"
	fi
done
CURVES=( $result )
for i in ${CURVES[@]}; do all_curves="${all_curves:+$all_curves:}+$i"; done

# Test each signature algo promiscuously and remove any that will never work
result=""
for tgt in ${PKSIGS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:$all_ciphers:$all_curves:+$tgt -p $PORT $IP > /dev/null 2>&1
	then
		debug "pksig $tgt is usable"
		result="${result:+$result }$tgt"
	fi
done
PKSIGS=( $result )
for i in ${KX[@]}; do all_pksigs="${all_curves:+$all_curves:}+$i"; done

total=$(( ${#PROTOS[@]} * ${#KX[@]} * ${#CIPHERS[@]} * ${#MACS[@]} + ${#CURVES[@]} + ${#PKSIGS[@]} + ${#v2_ciphers[@]} ))
i=0

if [ "$total" = 0 ]; then
	echo "Nothing worked! Does \`gnutls-cli --insecure -p $PORT $IP\` work?" >&2
	exit
fi

[ -t 1 ] && echo -en '\r\e[K'
printf '%-11s %-17s %-10s %-11s %-15s %-11s\n' "Proto" "Cipher" "MAC" "KeX" "Curve" "PK-Sig"
echo "------------------------------------------------"
for v2_cipher in ${v2_ciphers[@]}
do
	i=$(( $i + 1 ))
	OK=0
	_mac=`openssl ciphers -v -ssl2 | grep ^$v2_cipher | grep -Eo 'Mac=[^ ]+' | cut -d'=' -f2`
	_kx=`openssl ciphers -v -ssl2 | grep ^$v2_cipher | grep -Eo 'Kx=[^( ]+' | cut -d'=' -f2`
	[ -t 1 ] && printf '\r\e[K%-7s %-17s %-10s %-11s (%d / %d)' "SSL2.0" $v2_cipher $_mac $_kx $i $total
	echo -ne $request | openssl s_client -quiet -connect $HOST:$PORT -ssl2 -cipher $v2_cipher 2>&1 | grep -q 'ssl handshake failure\|write:errno=104' || OK=1
	if [ $OK -eq 1 ]
	then
		[ -t 1 ] && echo -en '\r\e[K'
		printf '\e[1;31m%-7s %-17s %-10s %-11s\n\e[00m' "SSL2.0" $v2_cipher $_mac $_kx
#		openssl ciphers -v -ssl2 | grep ^$i || echo "No match for $i"
	fi
done

for pksig in ${PKSIGS[@]}; do
for curve in ${CURVES[@]}; do
for proto in ${PROTOS[@]}; do
for kx in ${KX[@]}; do
for cipher in ${CIPHERS[@]}; do
for mac in ${MACS[@]}; do
	i=$(( $i + 1 ))
	printf '\r%-11s %-17s %-10s %-11s %-15s %-11s (%d / %d)' $proto $cipher $mac $kx $curve $pksig $i $total
	if echo -ne $request | gnutls-cli --insecure --priority NONE:+$proto:+$kx:+$mac:+COMP-NULL:+$cipher:+$curve:+$pksig -p $PORT $IP > /dev/null 2>&1; then
		[ -t 1 ] && echo -en "\r\e[K"
		[ $mac = "MD5" ] && echo -ne '\e[1;31m'
		[ $cipher = "ARCFOUR-40" ] && echo -ne '\e[1;31m'
		printf "%-11s %-17s %-10s %-11s %-15s %-11s\n" $proto $cipher $mac $kx $curve $pksig
		echo -ne '\e[00m'
	fi
done
done
done
done
done
done

printf "\r%80s\r\n" ""
