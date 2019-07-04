#!/bin/bash -eux

# From https://reactpaths.com/how-to-get-https-working-in-localhost-development-environment-f17de34af046

# Whatever the path the script is launched from, assume
# we're in the script folder.
READLINK=$(which greadlink || which readlink)
cd $($READLINK -e $(dirname $BASH_SOURCE))

rm -rf certs/*
mkdir -p certs

# Generate a CA
openssl genrsa -out certs/root.key 2048
openssl req \
    -x509 -new -nodes -sha256 -days 50000 \
    -key certs/root.key \
    -out certs/root.crt \
    -subj "/C=IN/ST=State/L=City/O=Organization/OU=root/CN=localhost"

generate_certificate(){
    # Generate a CSR
    openssl req \
    -new -nodes \
    -out "certs/${1}.csr" \
    -keyout "certs/${1}.key" \
    -config <(echo " \
        [ req ]
        default_bits = 2048
        encrypt_key = no
        default_md = sha256
        utf8only = yes
        string_mask = utf8only
        prompt = no
        distinguished_name = dn
        req_extensions = reqext
        x509_extensions = reqext

        [dn]
        0.domainComponent = "localhost"
        organizationName = "Vault Cli Test"
        organizationalUnitName = "${1}"
        commonName = "localhost"

        [reqext]
        keyUsage = critical,digitalSignature,keyEncipherment
        extendedKeyUsage = serverAuth,clientAuth
        subjectKeyIdentifier = hash
        subjectAltName = DNS:localhost
    ")

    # Generate the certificate
    openssl x509 \
    -req \
    -sha256 -days 50000 \
    -in certs/"${1}.csr" \
    -CA certs/root.crt -CAkey certs/root.key -CAcreateserial \
    -out certs/"${1}.crt" \

    cat certs/"${1}.key" certs/"${1}.crt" > certs/"${1}.pem"
    cat certs/"${1}.crt" certs/root.crt > certs/"${1}-chain.crt"
}

generate_certificate server
generate_certificate client
