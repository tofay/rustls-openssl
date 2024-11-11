#!/bin/bash
set -eux
openssl s_server -4 -port '4443' -cert tests/certs/localhost.crt  -key tests/certs/localhost.key -debug > tests/openssl.log 2>&1 &
sleep 5
openssl_pid=$!
port=$(ss -tpln | grep "pid=$openssl_pid" | cut -d':' -f 2 | cut -d' ' -f 1)
export RUSTLS_OPENSSL_PORT=4443
ss -tpln | grep openssl
cargo test --features x25519 || /bin/true
ss -tpln | grep openssl
sleep 1


openssl x509 -req -in $localhost.csr -CA RootCA.crt -CAkey RootCA.key -CAcreateserial -out $localhost.crt -days 730 -sha256 -extfile $localhost.v3.ext
openssl req -new -nodes -out localhost.csr  -key localhost.key -subj '/CN=My Firewall/C=AT/ST=Vienna/L=Vienna/O=MyOrg'

openssl x509 -req -in localhost.csr -CA RootCA.pem -CAkey RootCA.key -CAcreateserial -out localhost.pem -days 730 -sha256 -extfile localhost.v3.ext
