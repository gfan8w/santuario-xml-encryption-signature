/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.coheigea.santuario.xmlencryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.namespace.QName;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.Assert;

/**
 * This tests using the DOM API of Apache Santuario - XML Security for Java for XML Encryption.
 */
public class EncryptionDOMTest extends org.junit.Assert {

    // Encrypt + Decrypt an XML Document using the DOM API
    @org.junit.Test
    public void testEncryptionUsingDOMAPI() throws Exception {

        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream("plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, true);

        // Set up the Key
        KeyStore keyStore = KeyStore.getInstance("jks");
        // 使用程序原来带有的jks
//        keyStore.load(
//            this.getClass().getClassLoader().getResource("servicestore.jks").openStream(),
//            "sspass".toCharArray()
//        );
//        X509Certificate cert = (X509Certificate)keyStore.getCertificate("myservicekey");

        // 使用自己生成的jks，mydomain里带有公私钥
//        keyStore.load(
//                this.getClass().getClassLoader().getResource("keystore.jks").openStream(),
//                "123456".toCharArray()
//        );
//        X509Certificate cert = (X509Certificate)keyStore.getCertificate("mydomain");

        // 使用自己生成的pfx，
        keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(
                this.getClass().getClassLoader().getResource("keystore.jks").openStream(),
                "123456".toCharArray()
        );
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("mydomain");

        // 使用一个自己导出的公钥
        cert = readCertKey(new File(this.getClass().getClassLoader().getResource("my_domain.pem").getFile()));
        PublicKey publicKey = cert.getPublicKey();

        // 使用自己获取得到的 pubKey：
        publicKey = readPublicKey(new File(this.getClass().getClassLoader().getResource("my_domain_pubkey.pem").getFile()));


        // Set up the secret Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey secretKey = keygen.generateKey();

        // Encrypt using DOM
        List<QName> namesToEncrypt = new ArrayList<QName>();
        namesToEncrypt.add(new QName("urn:example:po", "PaymentInfo"));
        EncryptionUtils.encryptUsingDOM(
            document, namesToEncrypt, "http://www.w3.org/2001/04/xmlenc#aes128-cbc", secretKey,
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", publicKey, false
        );
        System.out.println("Print xml doc:");
        XMLUtils.outputDOM(document, System.out);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        Assert.assertEquals(nodeList.getLength(), 0);

        // Decrypt using DOM， 这里得到的privateKey类型是 RSAPrivatecrtkeyImpl
        Key privateKey = keyStore.getKey("mydomain", "123456".toCharArray());

        // 使用自己导出的私钥来解密，类型也是RSAPrivatecrtkeyImpl
        privateKey = readPrivateKey(new File(this.getClass().getClassLoader().getResource("mydomain.key").getFile()));

        EncryptionUtils.decryptUsingDOM(document,
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc", privateKey);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        System.out.println("Print xml doc after decrypt:");
        XMLUtils.outputDOM(document, System.out);
        Assert.assertEquals(nodeList.getLength(), 1);
    }


    public static RSAPublicKey readPublicKey(File file) throws Exception {
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.decodeBase64(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public RSAPrivateKey readPrivateKey(File file) throws Exception {
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.decodeBase64(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    public X509Certificate readCertKey(File file) throws Exception {
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert=(X509Certificate)cf.generateCertificate(new FileInputStream(file));
        return cert;
    }


}
