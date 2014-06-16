package org.opendaylight.snbi.certmgmt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyPairMgmt {

    protected static final Logger logger = LoggerFactory.getLogger(KeyPairMgmt.class);

    public static boolean createKeyStore(
            CertManagerConstants.STORE_TYPE storeType) {
        // Create a keystore with a randomly generated password to secure it
        //final String password = RandomStringUtils.randomAlphanumeric(CertManagerConstants.RANDOM_PASSWORD_NUM);

        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance(storeType == null ? KeyStore
                    .getDefaultType() : CertManagerConstants.STORE_TYPE.JCEKS
                    .toString());
        } catch (KeyStoreException e1) {
            e1.printStackTrace();
            return false;
        }

        // create file if not exists
        File keyStoreFile = new File(CertManagerConstants.KEY_STORE_FILE);
        try {
            if (!keyStoreFile.exists())
                keyStoreFile.createNewFile();
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        try (FileOutputStream fos = new FileOutputStream(keyStoreFile,false)) {
            try {
                keystore.load(null);
                keystore.store(fos,
                        CertManagerConstants.KEY_STORE_PASSWORD.toCharArray());
            } catch (KeyStoreException | NoSuchAlgorithmException
                    | CertificateException e) {
                e.printStackTrace();
                return false;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        System.out.println(keyStoreFile.getAbsolutePath());
        System.setProperty(CertManagerConstants.PROPERTY_KEYSTORE,
                keyStoreFile.getAbsolutePath());
        System.setProperty(CertManagerConstants.PROPERTY_KEYSTORE_PASSWORD,
                CertManagerConstants.KEY_STORE_PASSWORD);
        return true;
    }

    private static KeyStore getKeyStoreInstance(
            CertManagerConstants.STORE_TYPE storeType) {
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(storeType == null ? KeyStore
                    .getDefaultType() : CertManagerConstants.STORE_TYPE.JCEKS
                    .toString());
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return null;
        }
        return keystore;
    }

    private static Key getKeyFromStore(String alias, KeyStore keyStore,
            CertManagerConstants.STORE_TYPE storeType) {
        if (keyStore == null)
            return null;
        try (FileInputStream is = new FileInputStream(
                CertManagerConstants.KEY_STORE_FILE)) {
            keyStore.load(is,
                    CertManagerConstants.KEY_STORE_PASSWORD.toCharArray());
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
            return null;
        }
        Key key = null;
        try {
            key = keyStore.getKey(alias,
                    CertManagerConstants.CERT_PASSWORD.toCharArray());
        } catch (UnrecoverableKeyException | KeyStoreException
                | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        return key;

    }

    public static Certificate getCertificateFromKey(String alias,
            KeyStore keyStore, Key key) {
        if (key == null)
            return null;
        try {
            return (key instanceof PrivateKey ? keyStore.getCertificate(alias)
                    : null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    /*
     * Generate the keypair from the keystore
     */
    public static KeyPair getKeyPairFromStore(String alias,
            CertManagerConstants.STORE_TYPE storeType) {
        KeyStore keystore = getKeyStoreInstance(storeType);
        if (keystore == null)
            return null;
        Key key = getKeyFromStore(alias, keystore, storeType);
        if (key == null)
            return null;
        Certificate cert = getCertificateFromKey(alias, keystore, key);
        if (cert == null)
            return null;
        PublicKey publicKey = cert.getPublicKey();
        return new KeyPair(publicKey, (PrivateKey) key);
    }

    public static boolean addKeyAndCertToStore(KeyPair keyPair,
            CertManagerConstants.STORE_TYPE storeType, Certificate cert) {
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(storeType == null ? KeyStore
                    .getDefaultType() : CertManagerConstants.STORE_TYPE.JCEKS.toString());
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        }

        try (FileInputStream is = new FileInputStream(
                CertManagerConstants.KEY_STORE_FILE)) {
            keystore.load(is,
                    CertManagerConstants.KEY_STORE_PASSWORD.toCharArray());
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
            return false;
        }

        try {
            keystore.setKeyEntry(CertManagerConstants.KEY_STORE_ALIAS,
                    keyPair.getPrivate(),
                    CertManagerConstants.KEY_STORE_PASSWORD.toCharArray(),
                    new Certificate[] { cert });
            keystore.setCertificateEntry(
                    CertManagerConstants.KEY_STORE_CERT_ALIAS, cert);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        }

        try {
            keystore.store(new FileOutputStream(
                    CertManagerConstants.KEY_STORE_FILE),
                    CertManagerConstants.KEY_STORE_PASSWORD.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException
                | CertificateException | IOException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public static KeyPair generateKeyPair(CertManagerConstants.ALGORITHM ka) {
        return generateKeyPair(ka, null);
    }

    public static KeyPair generateKeyPair(CertManagerConstants.ALGORITHM ka,
            CertManagerConstants.PROVIDER kp) {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = (kp == null ? KeyPairGenerator.getInstance(ka.toString())
                    : KeyPairGenerator
                    .getInstance(ka.toString(), kp.toString()));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
        SecureRandom random = null;
        try {
            random = SecureRandom.getInstance(
                    CertManagerConstants.ALGORITHM.SHA1PRNG.toString(),
                    CertManagerConstants.PROVIDER.SUN.toString());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        if (random == null)
            keyGen.initialize(CertManagerConstants.KEY_LENGTH_1024);
        else
            keyGen.initialize(CertManagerConstants.KEY_LENGTH_1024, random);

        KeyPair keypair = keyGen.genKeyPair();
        PrivateKey privateKey = keypair.getPrivate();
        PublicKey publicKey = keypair.getPublic();

        System.out.println(privateKey);
        System.out.println(publicKey);

        return keypair;
    }

}