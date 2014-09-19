package org.opendaylight.snbi.southplugin;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * The Interface which describes the methods exposed by Certificate Manager.
 */
public interface ICertManager {
    public void printProviders();
    public void printWhiteListFromFile();
    public void printWhiteListFromStore();
    public void populateWhileListFromStore();
    // API , used by other bundles
    public PKCS10CertificationRequest generateCSRRequest(String... arguments);
    public X509Certificate generateX509Certificate(PKCS10CertificationRequest request, ContentSigner signer);
    public boolean compareCertificates(Certificate cert1, Certificate cert2);
    public HashMap<String,String> getCertificateInfo(X509Certificate cert);
    public X509Certificate getRootCACertificate();
    public String saveCertificate(X509Certificate cert);
    public X509Certificate getSavedCertificate(String alias);
    public String verifyCertificate(X509Certificate cert, Date date, PublicKey pub_key);
    public byte[] generateSignature(byte[] data, Certificate cert,String algorithm);
    public  boolean verifySignature(byte[] data,byte[] hash,Certificate cert,String algorithm);
}
