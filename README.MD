netty-dtls
=====


## self-signed certificate generate

1. Generate a private key for the CA:

```shell
openssl genrsa 2048 > ca.key
```

2. Generate the X509 certificate for the CA:

```shell
openssl req -new -x509 -nodes -days 365000 \
  -key ca.key \
  -out ca.crt \
  -subj "/C=cn/ST=Guangdong/L=Guangzhou/O=Ericsson, Inc./OU=ericsson/CN=ericsson.com/emailAddress=ehcayen@ericsson.com"
```

3. Generate the private key and certificate request for the server and client:

```shell
openssl req -newkey rsa:2048 -nodes -days 365000 \
  -keyout server.key \
  -out server.csr \
  -subj "/C=cn/ST=Guangdong/L=Guangzhou/O=Ericsson, Server Inc./OU=ericsson/CN=ericsson.com/emailAddress=ehcayen@ericsson.com"
openssl req -newkey rsa:2048 -nodes -days 365000 \
  -keyout client.key \
  -out client.csr \
  -subj "/C=cn/ST=Guangdong/L=Guangzhou/O=Ericsson, Client Inc./OU=ericsson/CN=ericsson.com/emailAddress=ehcayen@ericsson.com"
```

NOTE: subject must be difference with CA.

4. Generate the X509 certificate for the server and client;

```shell
openssl x509 -req -days 365000 -set_serial 01 -in server.csr -out server.crt -CA ca.crt -CAkey ca.key
openssl x509 -req -days 365000 -set_serial 01 -in client.csr -out client.crt -CA ca.crt -CAkey ca.key
```

5. Verify

```shell
openssl verify -CAfile ca.crt ca.crt server.crt 
openssl verify -CAfile ca.crt ca.crt client.crt 
```

6. Encode into netty recognize PKCS#8 pass challenge key.

```shell
openssl pkcs8 -v1 "PBE-SHA1-3DES" -topk8 -in server.key -out pkcs8_server.key
openssl pkcs8 -v1 "PBE-SHA1-3DES" -topk8 -in client.key -out pkcs8_client.key
```

Finally, you will get:

For server： ca.crt, server.crt, pkcs8_server.key
For client： ca.crt, client.crt, pkcs8_client.key



## dTLS with certificate

```shell
openssl s_server -CAfile ca.crt -cert server.crt -key pkcs8_server.key -dtls -accept 4739 -verify_return_error -Verify 1
openssl s_client -dtls -CAfile ca.crt -cert client.crt -key pkcs8_client.key -connect 127.0.0.1:4739 -debug
```

## http2 with certificate

1. GET

```shell
curl -k -v -L --output -s --compressed --http2-prior-knowledge -X CONNECT --cert client.crt --key pkcs8_client.key --cacert ca.crt https://127.0.0.1:8443/
```


2. POST

```shell
curl -k -vvvv \
 -H "Accept: application/json" \
 -H "Content-Type: application/json; charset=UTF-8" \
 -d '{"framework":"netty"}' \
 -L \
 --http2-prior-knowledge \
 --cert client.crt \
 --key pkcs8_client.key \
 --cacert ca.crt \
 https://127.0.0.1:8443/ \
 --output -
```

Use `output` to print response message:  

