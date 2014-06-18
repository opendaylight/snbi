package org.opendaylight.snbi.certmgmt;

import java.util.HashMap;

// constants defined for certificate management
final class CertManagerConstants {

    private static String workingDir = null;
    private static HashMap<String,String> defaults = null;
    static {
        workingDir = System.getProperty("user.dir");
        if (workingDir == null)
            workingDir = "/tmp/";
        else
            workingDir += "/";
        defaults = new HashMap<String,String> ();
        defaults.put("DOMAIN_NAME_DEFAULT","opendaylight.org");
        defaults.put("KEY_STORE_FILE","snbi.keystore.ks");
        defaults.put("SELF_SIGNED_CERT_FILE","selfsignedsnbi.cert");
        defaults.put("HARDWARE_CERT_FILE","whitelist.txt");
        defaults.put("KEY_STORE_PASSWORD","snbitestkeystore");
        defaults.put("CERT_PASSWORD","snbitestcertificate");
        defaults.put("KEY_STORE_ALIAS","snbi.selfkey");
        defaults.put("KEY_STORE_CERT_ALIAS","snbi.selfcert");
    }

    public static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

    public static final String DOMAIN_NAME_DEFAULT = defaults.get("DOMAIN_NAME_DEFAULT");
    public static final String KEY_CERT_PATH = workingDir;

    public static final int KEY_LENGTH_1024 = 1024;
    public static final int KEY_LENGTH_576 = 576;
    public static final int RANDOM_PASSWORD_NUM = 24;
    public static final String KEY_STORE_FILE = KEY_CERT_PATH+defaults.get("KEY_STORE_FILE");

    public static final String KEY_STORE_PASSWORD = defaults.get("KEY_STORE_PASSWORD");
    public static final String CERT_PASSWORD = defaults.get("CERT_PASSWORD");

    public static final String KEY_STORE_ALIAS = defaults.get("KEY_STORE_ALIAS");
    public static final String KEY_STORE_CERT_ALIAS = defaults.get("KEY_STORE_CERT_ALIAS");

    public static final String SELF_SIGNED_CERT_FILE = KEY_CERT_PATH
            + defaults.get("SELF_SIGNED_CERT_FILE");
    public static final String HARDWARE_CERT_FILE = KEY_CERT_PATH
            + defaults.get("HARDWARE_CERT_FILE");

    public static final String SNBI_STR = "snbi";

    public static final String PROPERTY_KEYSTORE = "javax.net.ssl.keyStore";
    public static final String PROPERTY_KEYSTORE_PASSWORD = "javax.net.ssl.keyStorePassword";

    public static final String NONE = "None";

    public enum ALGORITHM {
        DH, DSA, RSA, EC, SHA1PRNG
    };

    public enum PROVIDER {
        BC, SUN
    };

    public enum STORE_TYPE {
        JCEKS, JKS, PKCS12, BKS
    };

    /*
     * SHA1withDSA MD2withRSA MD5withRSA SHA1withRSA SHA224withRSA SHA256withRSA
     * SHA384withRSA SHA512withRSA RIPEMD128withRSA RIPEMD160withRSA
     * RIPEMD256withRSA
     */

    public enum CERT_ALGORITHM {
        MD5WithRSAEncryption, SHA256WithRSAEncryption,SHA1withRSA
    }

    public enum CERT_FORMAT {
        PEM, DER
    }

    public enum CERT_TYPE {
        X509("X.509");

        private final String name;

        private CERT_TYPE(String s) {
            name = s;
        }

        public boolean equalsName(String otherName) {
            return (otherName == null) ? false : name.equals(otherName);
        }

        @Override
        public String toString() {
            return name;
        }
    };

}