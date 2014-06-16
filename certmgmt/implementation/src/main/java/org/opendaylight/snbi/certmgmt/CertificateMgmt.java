package org.opendaylight.snbi.certmgmt;

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
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateMgmt {

    protected static HashMap<String,String> defaults = new HashMap<String,String>();
    static {
        defaults.put("COUNTRY", "USA");
        defaults.put("ORGANIZATION", "ODL Community");
        defaults.put("TITLE", "SNBI Certificate by BC");
        defaults.put("STATE", "CALIFORNIA");
    }

    protected static final Logger logger = LoggerFactory
            .getLogger(CertificateMgmt.class);

    public static X509Certificate generateSelfSignedCertificate(
            String hostname,String provider, KeyPair pair) {
        X509Certificate cert = null;
        try {
            // Generate self-signed certificate
            X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
            builder.addRDN(BCStyle.C, defaults.get("COUNTRY"));
            builder.addRDN(BCStyle.O, defaults.get("ORGANIZATION"));
            builder.addRDN(BCStyle.ST, defaults.get("STATE"));
            builder.addRDN(BCStyle.T, defaults.get("TITLE"));
            builder.addRDN(BCStyle.CN, hostname);
            Calendar now = Calendar.getInstance();
            Date notBefore = now.getTime();
            System.out.println("Certificate Validitiyy start = "+ notBefore.toString());
            now.add(Calendar.YEAR, 3);
            Date notAfter = now.getTime();
            System.out.println("Certificate Validitiyy End = "+ notAfter.toString());
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                    builder.build(), serial, notBefore, notAfter,
                    builder.build(), pair.getPublic());

            ContentSigner sigGen = new JcaContentSignerBuilder(
                    CertManagerConstants.CERT_ALGORITHM.SHA256WithRSAEncryption.toString()).setProvider(provider
                            ).build(pair.getPrivate());
            cert = new JcaX509CertificateConverter().setProvider(
                    provider).getCertificate(
                            certGen.build(sigGen));
        } catch (Throwable t) {
            t.printStackTrace();
        }
        return cert;
    }

    public static void saveCertificate(X509Certificate cert, KeyPair keyPair,String fileName) {
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

    public static X509Certificate getSavedCertificate(String provider,String fileName) {
        X509Certificate cert = null;
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

    public static void printCertificate(X509Certificate cert) {
        if (cert == null)
            return;
        System.out.println("Printing X509Certificate");
        System.out.println(" ------------------- START -------------------");
        System.out.println(cert);
        System.out.println(" -------------------  END  -------------------");
    }

    public static String verifyCertificate(X509Certificate cert, Date date, PublicKey pub_key) {
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

    /* ********************** NOT TESTED ******************************************************* */

    public static X509Certificate sign(CertificationRequest inputCSR,
            PrivateKey caPrivate, KeyPair pair) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, IOException, OperatorCreationException,
            CertException {

        PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(
                inputCSR);
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, defaults.get("COUNTRY"));
        builder.addRDN(BCStyle.O, defaults.get("ORGANIZATION"));
        builder.addRDN(BCStyle.ST, defaults.get("STATE"));
        builder.addRDN(BCStyle.T, defaults.get("TITLE"));
        builder.addRDN(BCStyle.CN, inputCSR.getSignature());
        Calendar now = Calendar.getInstance();
        Date notBefore = now.getTime();
        System.out.println("Certificate Validitiyy start = "+ notBefore.toString());
        now.add(Calendar.YEAR, 3);
        Date notAfter = now.getTime();
        System.out.println("Certificate Validitiyy End = "+ notAfter.toString());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                builder.build(), serial, notBefore, notAfter,
                builder.build(), pair.getPublic());

        ContentSigner sigGen = new JcaContentSignerBuilder(
                CertManagerConstants.CERT_ALGORITHM.SHA256WithRSAEncryption.toString()).setProvider(CertManagerConstants.BC).build(pair.getPrivate());


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

}