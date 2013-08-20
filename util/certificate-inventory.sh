#!/bin/bash

##############################################
# Author: Oscar Koeroo <oscar.koeroo@kpn.com>
# Office: CISO / Red Team - Ethical Hacker
# Project: Certs-on-Fire
##############################################

################# Global vars #################
TYPE=""
OUTPUT_FILE="/tmp/$(basename $0).$(date +%Y-%m-%d_%H:%M_%S).csv"
TMP_FILE="/tmp/$(basename $0).$$.tmp"
TIMEOUT=5
PARA=1000


################# Functions ##################
usage() {
    echo "`basename $0` { [-o | --output ] <output file> } {-type [http|smtp|pop3|imap|ftp] } targethost:portnum {targethost:portnum {targethost:portnum {targethost:portnum ... } } }"
    exit 1
}

function number_is_octet() {
    OCTET=$1

    regex="[0-9]+"
    if [[ "$OCTET" =~ $regex ]]; then
        if [ $OCTET -lt 256 ]; then
            return 0
        fi
    fi
    echo "Error: Input is not an octet for an IP address: $OCTET"
    return 1
}

downloadcertificate() {
    HOST=$1
    PORT=$2

    echo "$HOST:$PORT"

    # Download the certificate, optionally with a specific StartTLS type
    if [ -n "$TYPE" ]; then
        echo | timeout 5 openssl s_client -connect ${HOST}:${PORT} -starttls $TYPE 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "${TMP_FILE}"
    else
        echo | timeout 5 openssl s_client -connect ${HOST}:${PORT} 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "${TMP_FILE}"
    fi

    if [ ! -s "${TMP_FILE}" ]; then
        rm "${TMP_FILE}"
        return 1
    fi

    KEYSIZE=$(openssl x509 -text -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/^[[:blank:]]*//' | grep "RSA Public Key:" | cut -d')' -f 1 | cut -d'(' -f 2 | cut -d" " -f 1)
    SUBJECT=$(openssl x509 -subject -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/subject= //' -e 's/"/""/g')
    ISSUER=$(openssl x509 -issuer -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/issuer= //' -e 's/"/""/g')
    START_DT=$(openssl x509 -startdate -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/notBefore=//' -e 's/"/""/g')
    END_DT=$(openssl x509 -enddate -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/notAfter=//' -e 's/"/""/g')
    SERIAL=$(openssl x509 -serial -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/serial=//' -e 's/"/""/g')
    SANS=$(openssl x509 -text -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/^[[:blank:]]*//' | grep "DNS:")

    if [ "$ISSUER" = "$SUBJECT" ]; then
        SELF_SIGNED="yes"
    else
        SELF_SIGNED="no"
    fi

    echo "\"${HOST}\",\"${PORT}\",\"$SUBJECT\",\"$ISSUER\",\"$KEYSIZE\",\"$SERIAL\",\"$START_DT\",\"$END_DT\",\"$SELF_SIGNED\",\"$SANS\"" >> "$OUTPUT_FILE"


    rm "${TMP_FILE}"
    return 0
}

print_format_error_ip_block() {
    echo "The subnet $SUBNET needs to be written with 4 octets and a mask, example: 1.2.3.4/24" >&2
}

valid_ip() {
    IP=$1
    # Check if the numbers are IP addresses or too high/low
    OCTET_1=$(echo $IP | cut -d'.' -f 1)
    OCTET_2=$(echo $IP | cut -d'.' -f 2)
    OCTET_3=$(echo $IP | cut -d'.' -f 3)
    OCTET_4=$(echo $IP | cut -d'.' -f 4)

    number_is_octet $OCTET_1 || return 1
    number_is_octet $OCTET_2 || return 1
    number_is_octet $OCTET_3 || return 1
    number_is_octet $OCTET_4 || return 1

    return 0
}

valid_ip_block() {
    BLOCK=$1

    #Check if 4 octets are provided
    SUBNET=$(echo $BLOCK | cut -d'/' -f 1)
    TST=$(echo $SUBNET | cut -d'.' -f 4)
    if [ -z "$TST" ] || [ "$SUBNET" = "$TST" ]; then
        echo "The subnet $SUBNET needs to be written with 4 octets and a mask, example: 1.2.3.4/24" >&2
        return 1
    fi

    # Check mask
    MASK=$(echo $BLOCK | cut -d'/' -f 2)
    if [ -z $MASK ] || [ $MASK = $BLOCK ]; then
        print_format_error_ip_block
        return 1
    fi

    # Check mask value
    OCT_CNT=$(($MASK/8))
    if [ $OCT_CNT -ge 4 ]; then
        echo "The subnet mask is too big, example: 1.2.3.4/24" >&2
        exit 1
    fi

    # Check if the numbers are IP addresses or too high/low
    valid_ip $SUBNET
    RC=$?
    if [ $RC -ne 0 ]; then
        echo "The block IP is not OK, use 1.2.3.4, below 255." >&2
        exit 1
    fi

    echo "Valid block: ${SUBNET}/${MASK}" >&2
    return 0
}

calc_begin_ip() {
    BLOCK=$1
    if [ -z $BLOCK ]; then
        return 1
    fi

    USABLE_RANGE_RAW=$(sipcalc $BLOCK | grep "Usable range" | cut -d'-' -f 2 | sed -e 's/[[[:blank:]]//g')
    echo $USABLE_RANGE_RAW

    return 0
}

calc_end_ip() {
    BLOCK=$1
    if [ -z $BLOCK ]; then
        return 1
    fi

    USABLE_RANGE_RAW=$(sipcalc $BLOCK | grep "Usable range" | cut -d'-' -f 3 | sed -e 's/[[[:blank:]]//g')
    echo $USABLE_RANGE_RAW

    return 0
}


################## MAIN ###################

if [ -z "$1" ]; then
    usage
elif [ "$1" = "-type" ]; then
    shift
    if [ -z "$1" ]; then
        usage
    fi
    if [ "$1" = "smtp" ]; then
        TYPE="smtp"
        shift
    elif [ "$1" = "pop3" ]; then
        TYPE="pop3"
        shift
    elif [ "$1" = "imap" ]; then
        TYPE="imap"
        shift
    elif [ "$1" = "ftp" ]; then
        TYPE="ftp"
        shift
    elif [ "$1" = "http" ]; then
        shift
        #HTTPS and non-starttls SSL/TLS
        TYPE=""
    else
        #HTTPS and non-starttls SSL/TLS
        TYPE=""
    fi
elif [ "$1" = "-o" ] || [ "$1" = "--output" ]; then
    shift
    OUTPUT_FILE=$1
    shift
fi

# Add csv column title
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "\"Host\",\"Port\",\"Certificate Subject\",\"Issuer\",\"Keysize\",\"Serial\",\"Valid from date\",\"Valid until date\",\"self-signed\",\"Subject Alternative Names (DNS)\"" > "$OUTPUT_FILE"
fi


# Run over all of endpoints
while (( "$#" )); do
    OBJ=$1
    #echo "OBJ: $OBJ"
    MASK=$(echo $OBJ | cut -d'/' -f 2)
    #echo "MASK: $MASK"

    if [ -z "$MASK" ] || [ "$MASK" = "$OBJ" ]; then
        HOST=$(echo $OBJ | cut -d':' -f 1)
        PORT=$(echo $OBJ | cut -d':' -f 2)
        if [ -z $HOST ]; then
            echo "No Host provided"
            usage
            exit 1
        fi
        if [ -z $PORT ] || [ "$PORT" = "$OBJ" ]; then
            echo "No Port provided with the Host"
            usage
            exit 1
        fi

        DOWNLOADER="drssl"
        "${DOWNLOADER}" --quiet --host "$HOST" --port "$PORT" --csvfile "$OUTPUT_FILE" --timeout "$TIMEOUT"
    else
        BLOCK=$(echo $OBJ | cut -d':' -f 1)
        PORT=$(echo $OBJ | cut -d':' -f 2)
        if [ -z $BLOCK ]; then
            echo "No IP Block provided"
            usage
            exit 1
        fi
        if [ -z $PORT ] || [ "$PORT" = "$OBJ" ]; then
            echo "No Port provided with the block"
            usage
            exit 1
        fi

        valid_ip_block $BLOCK
        RC=$?
        if [ $RC -ne 0 ]; then
            exit 1
        fi

        BEGIN_IP=$(calc_begin_ip $BLOCK)
        END_IP=$(calc_end_ip $BLOCK)

        # Check begin
        valid_ip $BEGIN_IP
        RC=$?
        if [ $RC -ne 0 ]; then
            echo "The begin IP is not OK, use 1.2.3.4, below 255." >&2
            exit 1
        fi

        # Check end
        valid_ip $END_IP
        RC=$?
        if [ $RC -ne 0 ]; then
            echo "The end IP is not OK, use 1.2.3.4, below 255." >&2
            exit 1
        fi


        echo "IP from: \"$BEGIN_IP to: $END_IP\" on port $PORT"

        OCTET_BEG_1=$(echo $BEGIN_IP | cut -d'.' -f 1)
        OCTET_BEG_2=$(echo $BEGIN_IP | cut -d'.' -f 2)
        OCTET_BEG_3=$(echo $BEGIN_IP | cut -d'.' -f 3)
        OCTET_BEG_4=$(echo $BEGIN_IP | cut -d'.' -f 4)

        OCTET_END_1=$(echo $END_IP | cut -d'.' -f 1)
        OCTET_END_2=$(echo $END_IP | cut -d'.' -f 2)
        OCTET_END_3=$(echo $END_IP | cut -d'.' -f 3)
        OCTET_END_4=$(echo $END_IP | cut -d'.' -f 4)

        for ((i=$OCTET_BEG_1;i<=$OCTET_END_1;i++)); do
            for ((j=$OCTET_BEG_2;j<=$OCTET_END_2;j++)); do
                for ((k=$OCTET_BEG_3;k<=$OCTET_END_3;k++)); do
                    echo "Starting: $i.$j.$k.${OCTET_BEG_4}-${OCTET_END_4}"
                    echo
                    for ((l=$OCTET_BEG_4;l<=$OCTET_END_4;l++)); do
                        echo -n "."

                        HOST="$i.$j.$k.$l"
                        #DOWNLOADER="./download_certificate.sh"
                        DOWNLOADER="drssl"
                        CUR_PAR=$(ps | grep "${DOWNLOADER}" | wc -l | sed -e 's/[[:blank:]]//g')
                        while [ $CUR_PAR -ge $PARA ]; do
                            sleep 1
                            CUR_PAR=$(ps | grep "${DOWNLOADER}" | wc -l | sed -e 's/[[:blank:]]//g')
                        done

                        # actual download
                        #"${DOWNLOADER}" "$HOST" "$PORT" "$OUTPUT_FILE" "$TIMEOUT" "$TYPE" &
                        "${DOWNLOADER}" --quiet --host "$HOST" --port "$PORT" --csvfile "$OUTPUT_FILE" --timeout "$TIMEOUT" &
                    done
                    echo
                done
            done
        done
    fi

    shift
done


