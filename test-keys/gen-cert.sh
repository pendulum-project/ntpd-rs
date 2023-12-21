#! /bin/sh

# This script generates a private key/certificate for a server, and signs it with the provided CA key
# based on https://docs.ntpd-rs.pendulum-project.org/development/ca/

# Because this script generate keys without passwords set, they should only be used in a development setting.

if [ -z "$1" ]; then
	echo "usage: gen-cert.sh name-of-server [ca-name]"
	echo
	echo "This will generate a name-of-server.key, name-of-server.pem and name-of-server.chain.pem file"
	echo "containing the private key, public certificate, and full certificate chain (respectively)"
	echo
	echo "The second argument denotes the name of the CA be used (found in the files ca-name.key and ca-name.pem)"
	echo "If this is omitted, the name 'testca' will be used."
	exit
fi

NAME="${1:-ntpd-rs.test}"
CA="${2:-testca}"

# generate a key
openssl genrsa -out "$NAME".key 2048

# generate a certificate signing request
openssl req -batch -new -key "$NAME".key -out "$NAME".csr

# generate an ext file
cat >> "$NAME".ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $NAME
EOF

# generate the signed certificate with the provided CA
openssl x509 -req -in "$NAME".csr -CA "$CA".pem -CAkey "$CA".key -CAcreateserial -out "$NAME".pem -days 1825 -sha256 -extfile "$NAME".ext

# generate the full certificate chain version
cat "$NAME".pem "$CA".pem > "$NAME".chain.pem

# cleanup
rm "$NAME".csr
