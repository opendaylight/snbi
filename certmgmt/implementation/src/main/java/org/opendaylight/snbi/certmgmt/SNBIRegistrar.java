package org.opendaylight.snbi.certmgmt;

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

    // initialize the registrar.
    public void init() {
        logger.info("SNBIRegistrar::init start");
        printProviders();
        createKeyStore();
        populateWhileList();
        printWhiteList();
        selfSignCertificate();
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
        KeyPairMgmt.createKeyStore(CertManagerConstants.STORE_TYPE.JKS);
    }

    // create and self sign the certificate.
    // store the certificate and retreive it
    private void selfSignCertificate() {
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
                CertManagerConstants.STORE_TYPE.JKS, cert);
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
        System.out.println(" Start ..");
        SNBIRegistrar.INSTANCE.init();
        System.out.println(" END ..");
    }
}