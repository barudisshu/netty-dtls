netty-dtls
=====


## self-signed certificate generate

1. Generate a private key for the CA:

```shell
openssl genrsa 2048 > ca.key
```

2. Generate the X509 certificate for the CA:

```shell
openssl req -new -x509 -nodes -days 365000 -key ca.key -out ca.crt -subj "/C=cn/ST=Guangdong/L=Guangzhou/O=Cplier, Inc./OU=cplier/CN=cplier.com/emailAddress=galudisu@cplier.com"
```

3. Generate the private key and certificate request for the server and client:

```shell
openssl req -newkey rsa:2048 -nodes -days 365000 -keyout server.key -out server.csr -subj "/C=cn/ST=Guangdong/L=Guangzhou/O=Cplier, Inc./OU=cplier/CN=server.cplier.com/emailAddress=galudisu@cplier.com"
openssl req -newkey rsa:2048 -nodes -days 365000 -keyout client.key -out client.csr -subj "/C=cn/ST=Guangdong/L=Guangzhou/O=Cplier, Inc./OU=cplier/CN=client.cplier.com/emailAddress=galudisu@cplier.com"
```

NOTE: subject must be difference with CA.

4. Generate the X509 certificate for the server and client:

```shell
openssl x509 -req -days 365000 -set_serial 01 -in server.csr -out server.crt -CA ca.crt -CAkey ca.key -CAcreateserial
openssl x509 -req -days 365000 -set_serial 01 -in client.csr -out client.crt -CA ca.crt -CAkey ca.key -CAcreateserial
```

5. Verify

```shell
openssl verify -CAfile ca.crt ca.crt server.crt 
openssl verify -CAfile ca.crt ca.crt client.crt 
```

6. Encode into netty recognize PKCS#8 pass challenge key.

```shell
openssl pkcs8 -topk8 -in server.key -out pkcs8_server.key
openssl pkcs8 -topk8 -in client.key -out pkcs8_client.key
```

7. Generate truststore:

```shell
keytool -import -noprompt -file ca.crt -keystore truststore.jks -storepass cplier
```

8. Generate keystore for server:

```shell
openssl pkcs12 -export -in server.crt -inkey server.key -out server.pkcs12 -passout pass:server -name server -noiter -nomaciter
keytool -importkeystore -srckeystore server.pkcs12 -srcstoretype PKCS12 -deststoretype pkcs12 -destkeystore server.jks -srcstorepass server -deststorepass server
```

8. Generate keystore for client:

```shell
openssl pkcs12 -export -in client.crt -inkey client.key -out client.pkcs12 -passout pass:client -name client -noiter -nomaciter
keytool -importkeystore -srckeystore client.pkcs12 -srcstoretype PKCS12 -deststoretype pkcs12 -destkeystore client.jks -srcstorepass client -deststorepass client
```

9. Verify

```shell
keytool --list -keystore client.jks -storepass client
keytool --list -keystore server.jks -storepass server
keytool --list -keystore truststore.jks -storepass cplier
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
curl -k -vvv -L --http2-prior-knowledge --output - -X CONNECT --cert client.crt --key pkcs8_client.key --cacert ca.crt https://127.0.0.1:8443/
```


2. POST

```shell
curl -k -vvvv \
 -H "Accept: application/json" \
 -H "Content-Type: application/json; charset=UTF-8" \
 -d '{"framework":"netty"}' \
 -L \
 --http2-prior-knowledge \
 --output - \
 --cert client.crt \
 --key pkcs8_client.key \
 --cacert ca.crt \
 https://127.0.0.1:8443/
```

Use `output` to print response message:  

