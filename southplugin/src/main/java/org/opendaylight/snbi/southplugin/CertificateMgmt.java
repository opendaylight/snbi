/*
 * Copyright (c) 2014, 2015 Ericsson Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Class to manage certificates
public class CertificateMgmt {

    // a static map to keep default values for certificate management
    public static HashMap<String,String> defaults = null;
    static {
        defaults = new HashMap<String,String>();
//        defaults.put("COUNTRY", "USA");
//        defaults.put("ORGANIZATION", "ODL Community");
      //  defaults.put("TITLE", "SNBI Certificate by BC");
       // defaults.put("STATE", "CALIFORNIA");
       // defaults.put("LOCALITY", "SANJOSE");
       // defaults.put("EMAIL", "snbi-dev@lists.opendaylight.org");
    }

    protected static final Logger logger = LoggerFactory
            .getLogger(CertificateMgmt.class);

    // create and sign the self signed certificate during startup
    public static X509Certificate generateSelfSignedCertificate(
            String hostname,String provider, KeyPair pair) {
        logger.info("Creating self signed certificate ");
        X509Certificate cert = null;
        try {
            // Generate self-signed certificate
            X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
//            builder.addRDN(BCStyle.C, defaults.get("COUNTRY"));
//            builder.addRDN(BCStyle.O, defaults.get("ORGANIZATION"));
//            builder.addRDN(BCStyle.ST, defaults.get("STATE"));
           // builder.addRDN(BCStyle.T, defaults.get("TITLE"));
           // builder.addRDN(BCStyle.L, defaults.get("LOCALITY"));
            //builder.addRDN(BCStyle.E, defaults.get("EMAIL"));
            builder.addRDN(BCStyle.SN, BigInteger.valueOf(System.currentTimeMillis()).toString());
            builder.addRDN(BCStyle.CN, hostname);

            ContentSigner sigGen = new JcaContentSignerBuilder(
                    CertManagerConstants.CERT_ALGORITHM.SHA1withRSA.toString()).setProvider(provider
                            ).build(pair.getPrivate());
            Calendar now = Calendar.getInstance();
            Date notBefore = now.getTime();
            now.add(Calendar.YEAR, 3);
            Date notAfter = now.getTime();
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                    builder.build(), serial, notBefore, notAfter,
                    builder.build(), pair.getPublic());
            cert = new JcaX509CertificateConverter().setProvider(
                    provider).getCertificate(
                            certGen.build(sigGen));
        } catch (Throwable t) {
            t.printStackTrace();
        }
        logger.info("Created self signed certificate ");
        return cert;
    }

    // save the certificate locally
    public static void saveCertificate(X509Certificate cert, KeyPair keyPair,String fileName) {
        logger.info("Saving certificate "+fileName);
        if (cert == null)
            return;
        PEMWriter pemWriter = null;
        try {
            pemWriter = new PEMWriter(new FileWriter(fileName));
            pemWriter.writeObject(cert);
            pemWriter.flush();
            pemWriter.writeObject(keyPair.getPrivate());
            pemWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        } finally {
            try {
                pemWriter.close();
            } catch (IOException e) {
            }
        }
    }

    // retrieve saved certificate from file
    public static X509Certificate getSavedCertificate(String provider,String fileName) {
        X509Certificate cert = null;
        logger.info("Retrieving certificate "+fileName);
        FileReader fileReader;
        try {
            fileReader = new FileReader(fileName);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
        PEMParser pemParser = new PEMParser(fileReader);
        Object privatekey;
        try {
            privatekey = pemParser.readObject();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } finally {
            try {
                pemParser.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        if (privatekey == null)
            return null;
        X509CertificateHolder certHolder = (X509CertificateHolder)privatekey;
        try {
            return new JcaX509CertificateConverter().setProvider(provider)
                    .getCertificate( certHolder );
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return cert;
    }

    // print the certificate to console and return the certificate String
    public static String printCertificate(X509Certificate cert) {
        logger.info("Printing X509Certificate");
        if (cert == null)
            return null;
        logger.info(" ------------------- START -------------------");
        logger.info(cert.toString());
        logger.info(" -------------------  END  -------------------");
        return cert.toString();
    }

    // verify the certificate by date and public key. returns error message .
    public static String verifyCertificate(X509Certificate cert, Date date, PublicKey pub_key) {
        logger.info("Verify X509Certificate");
        String message = "";
        try {
            if (date != null)
                cert.checkValidity(date);
        } catch (CertificateException e) {
            message = "CERTIFICATE VALIDATION ERROR :: "+e.getMessage()+"\n";
        }
        try {
            if (pub_key != null)
                cert.verify(cert.getPublicKey());
        } catch (InvalidKeyException | CertificateException
                | NoSuchAlgorithmException | NoSuchProviderException
                | SignatureException e) {
            message += "CERTIFICATE VALIDATION ERROR  :: "+e.getMessage();
        }

        if (message.trim().length() == 0)
            message = "CERTIFICATE VALIDATION SUCESS";

        return message;

    }

    // generate a certificate signing request
    public static PKCS10CertificationRequest generateCSRRequest(String name,KeyPair pair) throws Exception {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
//        builder.addRDN(BCStyle.C, defaults.get("COUNTRY"));
//        builder.addRDN(BCStyle.O, defaults.get("ORGANIZATION"));
       // builder.addRDN(BCStyle.ST, defaults.get("STATE"));
       // builder.addRDN(BCStyle.T, defaults.get("TITLE"));
        builder.addRDN(BCStyle.SN, BigInteger.valueOf(System.currentTimeMillis()).toString());
        builder.addRDN(BCStyle.CN, name);
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                builder.build(), pair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(CertManagerConstants.CERT_ALGORITHM.SHA1withRSA.toString());
        ContentSigner signer = csBuilder.build(pair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        return csr;
    }

    // build a certificate chain with root certificate and new x509 certificate.
    public static X509Certificate[] buildChain(String provider, KeyPair pair) throws Exception {
        X509Certificate rootCert = CertificateMgmt
                .getSavedCertificate(CertManagerConstants.BC,CertManagerConstants.SELF_SIGNED_CERT_FILE);
        KeyPair rootPair = KeyPairMgmt.getKeyPairFromStore(CertManagerConstants.KEY_STORE_ALIAS,CertManagerConstants.KEY_STORE_CERT_ALIAS,  CertManagerConstants.STORE_TYPE.JKS);
        KeyPair keyPair = KeyPairMgmt
                .generateKeyPair(CertManagerConstants.ALGORITHM.RSA);
        PKCS10CertificationRequest request = generateCSRRequest("Node",pair);
        Calendar now = Calendar.getInstance();
        Date notBefore = now.getTime();
        now.add(Calendar.YEAR, 3);
        Date notAfter = now.getTime();
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                request.getSubject(), serial, notBefore, notAfter,
                request.getSubject(), rootCert.getPublicKey());
        ContentSigner sigGen = new JcaContentSignerBuilder(
                CertManagerConstants.CERT_ALGORITHM.SHA1withRSA.toString()).setProvider(provider
                        ).build(rootPair.getPrivate());
        X509Certificate issuedCert = new JcaX509CertificateConverter().setProvider(
                provider).getCertificate(
                        certGen.build(sigGen));
        return new X509Certificate[] { issuedCert, rootCert };
    }

    // utility metjhod to sign the csr with local CA
    public static X509Certificate signCSR(CertificationRequest inputCSR,
            PrivateKey caPrivate, KeyPair pair) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, IOException, OperatorCreationException,
            CertException {

        PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(
                inputCSR);
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
//        builder.addRDN(BCStyle.C, defaults.get("COUNTRY"));
//        builder.addRDN(BCStyle.O, defaults.get("ORGANIZATION"));
        //builder.addRDN(BCStyle.ST, defaults.get("STATE"));
       // builder.addRDN(BCStyle.T, defaults.get("TITLE"));
        builder.addRDN(BCStyle.CN, inputCSR.getSignature());
        Calendar now = Calendar.getInstance();
        Date notBefore = now.getTime();
        now.add(Calendar.YEAR, 3);
        Date notAfter = now.getTime();
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                builder.build(), serial, notBefore, notAfter,
                builder.build(), pair.getPublic());
        ContentSigner sigGen = new JcaContentSignerBuilder(
                CertManagerConstants.CERT_ALGORITHM.SHA1withRSA.toString()).setProvider(CertManagerConstants.BC).build(pair.getPrivate());
        X509CertificateHolder holder = certGen.build(sigGen);
        Certificate eeX509CertificateStructure = holder.toASN1Structure();
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance(CertManagerConstants.CERT_TYPE.X509.toString(), CertManagerConstants.BC);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        // Read Certificate
        InputStream is1 = new ByteArrayInputStream(
                eeX509CertificateStructure.getEncoded());
        X509Certificate theCert = null;
        try {
            theCert = (X509Certificate) cf.generateCertificate(is1);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        is1.close();
        return theCert;
    }

    // method to revoke a certificate
    public static void createCRL(String name) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
//        builder.addRDN(BCStyle.C, defaults.get("COUNTRY"));
//        builder.addRDN(BCStyle.O, defaults.get("ORGANIZATION"));
       // builder.addRDN(BCStyle.ST, defaults.get("STATE"));
       // builder.addRDN(BCStyle.T, defaults.get("TITLE"));
        builder.addRDN(BCStyle.SN, BigInteger.valueOf(System.currentTimeMillis()).toString());
        builder.addRDN(BCStyle.CN, name);
        Calendar now = Calendar.getInstance();
        Date notBefore = now.getTime();
        now.add(Calendar.YEAR, 3);
        Date notAfter = now.getTime();
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(builder.build(),notBefore);
        crlGen.setNextUpdate(notAfter);
    }

    // create signature with the root ca private key
    public static byte[] generateSignature(byte[] data, Certificate cert,String algorithm) {
        Signature signer = null;
        KeyPair rootPair = KeyPairMgmt.getKeyPairFromStore(CertManagerConstants.KEY_STORE_ALIAS, CertManagerConstants.KEY_STORE_CERT_ALIAS, CertManagerConstants.STORE_TYPE.JKS);
        try {
            signer = Signature.getInstance(algorithm, CertManagerConstants.BC);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
        try {
            signer.initSign(rootPair.getPrivate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
        try {
            signer.update(data);
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
        try {
            return signer.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    //verify the signature . first generate the signature and compare with both hash
    public static boolean verifySignature(byte[] data,byte[] hash,Certificate cert,String algorithm) {
        byte[] newhash = generateSignature(data,cert,algorithm);
        return Arrays.equals(hash, newhash);
    }

    /* Misc Methods not used */

    // create signature by passing the certificate
    public static byte[] sign(Certificate cert,KeyPair pair) {
        ContentSigner signGen = null;
        X509CertificateHolder certHolder = new X509CertificateHolder(cert);

        try {
            signGen =  new JcaContentSignerBuilder(CertManagerConstants.CERT_ALGORITHM.SHA1withRSA.toString()).setProvider(CertManagerConstants.BC).build(pair.getPrivate());
        } catch (OperatorCreationException e) {
            e.printStackTrace();
            return null;
        }
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        try {
            gen.addSignerInfoGenerator(
                    new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                    .build(signGen,certHolder));
        } catch (OperatorCreationException e) {
            e.printStackTrace();
            return null;
        }
        return certHolder.getSignature();
    }

    // create signature another api
    public static byte[] sign(byte[] data,  KeyPair pair) {

        Signature signer = null;
        try {
            signer = Signature.getInstance(CertManagerConstants.CERT_ALGORITHM.SHA1withRSA.toString(), CertManagerConstants.BC);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
        try {
            signer.initSign(pair.getPrivate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
        try {
            signer.update(data);
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
        try {
            return signer.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

}
