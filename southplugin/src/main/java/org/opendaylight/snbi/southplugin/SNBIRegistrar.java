package org.opendaylight.snbi.southplugin;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// inner class to hold device info. Not used yet.
class DeviceInfo {
    public String ip;
    public String serialNum;
    public String domainName;

}

public enum SNBIRegistrar {
    INSTANCE;

    static {
        // adds the Bouncy castle provider to java security
        Security.addProvider(new BouncyCastleProvider());
    }
    private static final HashSet<String> hardwareKeySet = new HashSet<String>();
    private static final HashSet<String> domainNameSet = new HashSet<String>();
    private static final HashMap<String, DeviceInfo> deviceInfoMap = new HashMap<String, DeviceInfo>();
    protected static final Logger logger = LoggerFactory
            .getLogger(SNBIRegistrar.class);

    public static int ID = 1;

    // initialize the registrar.
    public void init() {
        logger.info("SNBIRegistrar::init start");
        printProviders();
        createKeyStore();
      //  populateWhileList();
      //  printWhiteList();
        selfSignRSACertificate();
        logger.info("SNBIRegistrar::init end");
    }

    public void printProviders() {
        Provider[] ps = Security.getProviders();
        for (int i = 0; i < ps.length; i++)
            logger.info("Security Provider " + ps[i].getName());
    }

    public void printWhiteList() {
        for (String key : hardwareKeySet)
            logger.info("Hardware Key = " + key);
    }

    // read the manufacturer keys from a file and populate in the map
    public void populateWhileList() {
        logger.info("SNBIRegistrar::populateKeySet");
        hardwareKeySet.clear();
        // create file if not exists
        File whilelist = new File(CertManagerConstants.HARDWARE_CERT_FILE);
        try {
            if (!whilelist.exists()) {
                logger.info("SNBIRegistrar::creating empty file "
                        + CertManagerConstants.HARDWARE_CERT_FILE);
                whilelist.createNewFile();
            }
        } catch (IOException e1) {
            e1.printStackTrace();
            return;
        }

        List<String> lines = new ArrayList<String>();
        try {
            lines = FileUtils.readLines(new File(
                    CertManagerConstants.HARDWARE_CERT_FILE));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        hardwareKeySet.addAll(new HashSet<String>(lines));
    }

    // utility to check if BC is available
    public static boolean verifyBouncyCastleInstance() {
        return (Security.getProvider(CertManagerConstants.PROVIDER.BC
                .toString()) == null ? false : true);
    }

    /* Private Methods */
    private void createKeyStore() {
        logger.info("KeyStore file path is "+CertManagerConstants.KEY_CERT_PATH);
        KeyPairMgmt.createKeyStore(CertManagerConstants.STORE_TYPE.JCEKS);
    }

    // create and self sign the certificate.
    // store the certificate and retreive it
    private void selfSignRSACertificate() {
        logger.info("SNBIRegistrar::selfSignCertificate");
        // generate key pair
        KeyPair keyPair = KeyPairMgmt
                .generateKeyPair(CertManagerConstants.ALGORITHM.RSA);
        X509Certificate cert = CertificateMgmt
                .generateSelfSignedCertificate(CertManagerConstants.SNBI_STR,
                        CertManagerConstants.BC, keyPair);
        logger.info("Created Self signed certificate ");
        CertificateMgmt.printCertificate(cert);
        logger.info("Saving Self signed certificate ");
        CertificateMgmt.saveCertificate(cert, keyPair,
                CertManagerConstants.SELF_SIGNED_CERT_FILE);
        logger.info("Saving Key and Certificate to Key store ");
        KeyPairMgmt.addKeyAndCertToStore(keyPair,
                CertManagerConstants.STORE_TYPE.JCEKS, cert);
        logger.info("Retreiving Self signed certificate ");
        X509Certificate certSaved = CertificateMgmt.getSavedCertificate(
                CertManagerConstants.BC,
                CertManagerConstants.SELF_SIGNED_CERT_FILE);
        CertificateMgmt.printCertificate(certSaved);
        String message = CertificateMgmt.verifyCertificate(cert, Calendar
                .getInstance().getTime(), certSaved.getPublicKey());
        logger.info(message);
    }

    // for testing
    public static void main(String args[]) {
        System.out.println("Init Start ..");
        SNBIRegistrar.INSTANCE.init();
        System.out.println("Init END ..");
        System.out.println("Testing the API's . START");
        org.bouncycastle.pkcs.PKCS10CertificationRequest certRequest =
                SNBICAInterfaces.INSTANCE.generateCSRRequest(new String[]{"My Name","Ericsson","101"});
        System.out.println("Created the CSR "+certRequest.toString());
        X509Certificate certificate = SNBICAInterfaces.INSTANCE.generateX509Certificate(certRequest,null);
        System.out.println("Created the Certificate "+certificate.toString());
        HashMap<String,String> certInfo = SNBICAInterfaces.INSTANCE.getCertificateInfo(certificate);
        System.out.println("Certificate Values ");
        for (Map.Entry<String,String> entry : certInfo.entrySet()) {
            System.out.println(entry.getKey()+ "  =  "+entry.getValue());
        }
        String alias = SNBICAInterfaces.INSTANCE.saveCertificate(certificate);
        System.out.println("Saved the certificate with alias = "+alias);

        X509Certificate savedCert = SNBICAInterfaces.INSTANCE.getSavedCertificate(alias);
        System.out.println("Retreived the Certificate "+savedCert.toString());
        HashMap<String,String> savedCertInfo = SNBICAInterfaces.INSTANCE.getCertificateInfo(certificate);
        System.out.println("Saved Certificate Values ");
        for (Map.Entry<String,String> entry : savedCertInfo.entrySet()) {
            System.out.println(entry.getKey()+ "  =  "+entry.getValue());
        }
        byte[] data = {10,20,30};
        byte[] hashData = SNBICAInterfaces.INSTANCE.generateSignature(data, null,CertManagerConstants.CERT_ALGORITHM.SHA1withRSA.toString());
        System.out.println("Hash code for data is "+data.toString());
        byte[] data1 = {10,20,30};
        byte[] data2= {10,20,30,40};
        boolean dataSame1 = SNBICAInterfaces.INSTANCE.verifySignature(data1, hashData, null,CertManagerConstants.CERT_ALGORITHM.SHA1withRSA.toString());
        System.out.println(" Data Same = "+dataSame1);
        boolean dataSame2 = SNBICAInterfaces.INSTANCE.verifySignature(data2, hashData, null,CertManagerConstants.CERT_ALGORITHM.SHA1withRSA.toString());
        System.out.println(" Data Same = "+dataSame2);

        System.out.println("Testing the API's . END");

    }
}
