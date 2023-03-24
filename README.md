santuario-xml-encryption
===========

This project contains a number of tests that show how to use Apache Santuario
 - XML Security for Java to encrypt and decrypt XML documents. It contains the
following tests:

1) EncryptionDOMTest

This tests using the Apache XML Security for Java DOM API for XML Encryption.

2) EncryptionStAXTest

This tests using the new StAX-based (streaming) XML Encryption functionality
in Apache XML Security for Java 2.0.0.

3) EncryptionInteropTest

This tests encrypting using one API and decrypting using the other.

4) 生成一个keystore

`keytool -genkey -alias  mydomain  -keyalg RSA -keystore  keystore.jks -keysize 2048`

keystore.jks 包含公钥，私钥，密码：`123456`

`keytool -list -v -keystore  keystore.jks`

输入密码： `123456` , 查看 keystore 内的公私钥信息

导出证书，只有公钥和签名等信息，没有私钥，其编码可以是 `PEM` 和 `DER`。

`keytool -export -alias mydomain -storepass 123456 -file my_domain.cer -keystore keystore.jks`

使用 openssl 查看二进制内容（DER格式）

`openssl x509 -in my_domain.cer -inform der -text -noout`

改变格式，变为base64的 PEM 格式

`openssl x509 -in my_domain.cer -inform der -outform pem -out my_domain.pem`

从 cert 中取出pubkey：

`openssl x509 -pubkey -noout -in my_domain.pem  > my_domain_pubkey.pem`

通过使用Java的 keytool 把 java格式的`jks`变为`PKCS12`格式：
源store密码：`123456`
目标store密码： `123456`

`keytool -importkeystore -srckeystore keystore.jks -srcstoretype JKS -destkeystore keystorepk12.pfx -deststoretype PKCS12`

生成一个p12（pfx）文件后，导出 key，导出私钥，会提示输入密码，我们输入`123456`

`openssl pkcs12 -in keystorepk12.pfx -nodes -nocerts -out mydomain.key`

生成 private key 后，把 头部多余信息去掉， 以下信息去掉：
```
Bag Attributes
friendlyName: mydomain
localKeyID: 54 69 6D 65 20 31 36 37 39 34 38 30 32 32 37 34 37 30
Key Attributes: <No Attributes>
```
私钥文件中的头部，如果是`BEGIN RSA PRIVATE KEY` 表示是`PKCS#1`。
如果是`BEGIN PRIVATE KEY`是`PKCS#8`
具体的差别请参看：https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key/20065522#20065522


当然我们也能通过p12格式文件，生成证书，这里前面已经通过keytool生成了，这里忽略

`openssl pkcs12 -in keystorepk12.pfx -nokeys -out my_domain.cer`

```sql
Every X.509 certificate has a field called "Issuer" that specifies the entity that issued the certificate, and another field called "Subject" that identifies the entity to which the certificate is issued.

If the Issuer field in a certificate matches the Subject field of another certificate, the first certificate is said to be signed by the second certificate. This creates a chain of trust, where each certificate is signed by a higher-level certificate, until a self-signed root certificate is reached.

So, if you have a certificate, you can examine its Issuer field to see which certificate it was signed by. You can then repeat this process for that certificate until you reach the root certificate, which is self-signed and does not have an Issuer field that matches another certificate's Subject field. This root certificate represents the ultimate trust anchor for the certificate chain.
```
