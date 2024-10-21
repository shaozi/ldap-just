#!/bin/sh -x
CANAME=ldap_root_ca
openssl genrsa -aes256 -passout pass:ldap -out $CANAME.key 4096
# create certificate
openssl req -x509 -new -nodes -days 36500 \
  -passin pass:ldap \
  -key $CANAME.key -sha256 \
  -out $CANAME.crt \
  -subj '/CN=ROOT_CA/C=US/ST=CA/L=Fremont/O=LDAP'
# create certificate for service
MYCERT=ldap
openssl req -new -nodes \
  -out $MYCERT.csr \
  -newkey rsa:4096 \
  -keyout $MYCERT.key \
  -subj '/CN=LDAP/C=US/ST=CA/L=Fremont/O=LDAP'
# create a v3 ext file for SAN properties
cat >$MYCERT.v3.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = ldap
EOF
openssl x509 -req -sha256 -days 36500 \
  -passin pass:ldap \
  -extfile $MYCERT.v3.ext \
  -in $MYCERT.csr \
  -CA $CANAME.crt \
  -CAkey $CANAME.key \
  -out $MYCERT.crt
