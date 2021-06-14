netty-dtls
=====


## self-signed certificate generate

1.生成ca证书

```shell
openssl req -new -x509 -keyout ca.key -out ca.crt -days 36500
```
在本目录得到 ca.key 和 ca.crt 文件

2.生成服务端和客户端私钥

```shell
openssl genrsa -des3 -out server.key 1024
openssl genrsa -des3 -out client.key 1024
```

3.根据 key 生成 csr 文件

```shell
openssl req -new -key server.key -out server.csr
openssl req -new -key client.key -out client.csr
```


4.根据 ca 证书 server.csr 和 client.csr 生成 x509 证书

```shell
openssl x509 -req -days 36500 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
openssl x509 -req -days 36500 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

5.将 key 文件进行 PKCS#8 编码

```shell
openssl pkcs8 -v1 "PBE-SHA1-3DES" -topk8 -in server.key -out pkcs8_server.key
openssl pkcs8 -v1 "PBE-SHA1-3DES" -topk8 -in client.key -out pkcs8_client.key
```


最后得到有用的文件分别为

服务器端： ca.crt, server.crt, pkcs8_server.key
客户端端： ca.crt, client.crt, pkcs8_client.key


6. 查看命令

```shell
# openssl 查看证书细节
# 打印证书的过期时间
openssl x509 -in signed.crt -noout -dates
# 打印出证书的内容:
openssl x509 -in cert.pem -noout -text
# 打印出证书的系列号
openssl x509 -in cert.pem -noout -serial
# 打印出证书的拥有者名字
openssl x509 -in cert.pem -noout -subject
# 以RFC2253规定的格式打印出证书的拥有者名字
openssl x509 -in cert.pem -noout -subject -nameopt RFC2253
# 在支持UTF8的终端一行过打印出证书的拥有者名字
openssl x509 -in cert.pem -noout -subject -nameopt oneline -nameopt -escmsb
# 打印出证书的MD5特征参数
openssl x509 -in cert.pem -noout -fingerprint
# 打印出证书的SHA特征参数
openssl x509 -sha1 -in cert.pem -noout -fingerprint
# 把PEM格式的证书转化成DER格式
openssl x509 -in cert.pem -inform PEM -out cert.der -outform DER
# 把一个证书转化成CSR
openssl x509 -x509toreq -in cert.pem -out req.pem -signkey key.pem
# 给一个CSR进行处理, 颁发字签名证书, 增加CA扩展项
openssl x509 -req -in careq.pem -extfile openssl.cnf -extensions v3_ca -signkey key.pem -out cacert.pem
# 给一个CSR签名, 增加用户证书扩展项
openssl x509 -req -in req.pem -extfile openssl.cnf -extensions v3_usr -CA cacert.pem -CAkey key.pem -CAcreateserial
# 查看csr文件细节:
openssl req -in my.csr -noout -text
```

## with certificate

```bash
curl -k -v --cert client.crt --key pkcs8_client.key --cacert ca.crt https://localhost:8443/
```