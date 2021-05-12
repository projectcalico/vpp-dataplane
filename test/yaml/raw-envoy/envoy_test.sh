#!/bin/bash

create_ca_signed_cert () {
# source : https://stackoverflow.com/questions/21297139/how-do-you-sign-a-certificate-signing-request-with-your-certification-authority/21340898#21340898
  mkdir tmp.$1
  cd tmp.$1
  cp ../cacert.pem .
  cp ../cakey.pem .
  # Create CSR
  openssl req -config ../../openssl-server.cnf -newkey rsa:2048 -sha256 -nodes -out servercert.csr -outform PEM

  # Sign CSR
  touch index.txt
  echo '01' > serial.txt
  openssl ca -config ../../openssl-ca.cnf -policy signing_policy -extensions signing_req -out servercert.pem -infiles servercert.csr

  # teardown
  cp servercert.pem ../$1cert.pem
  cp serverkey.pem ../$1key.pem
  cd ..
}

if [ "$1" = "sync" ]; then
  rsync -avz --delete --exclude=docker-compose.yml --exclude=.git ../../* vq1:~/provision-kvpp/
  rsync -avz --delete --exclude=docker-compose.yml --exclude=.git ../../* vq2:~/provision-kvpp/
  echo "Then ssh vq2 & docker exec -it ipc iperf3 -c 127.0.0.1"
elif [ "$1" = "certs" ]; then
  rm -rf certs
  mkdir certs
  cd certs

  # Create CA certs
  openssl req -x509 -config ../openssl-ca.cnf -newkey rsa:4096 -sha256 -nodes -out cacert.pem -outform PEM

  create_ca_signed_cert server
  create_ca_signed_cert client
else
  echo "Usage"
  echo "$0 sync"
  echo "$0 certs"
fi
