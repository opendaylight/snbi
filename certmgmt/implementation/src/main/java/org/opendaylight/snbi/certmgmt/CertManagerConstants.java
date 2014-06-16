package org.opendaylight.snbi.certmgmt;

final class CertManagerConstants {

    public static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

    public static final String DOMAIN_NAME = "opendaylight.org";
    public static final String KEY_CERT_PATH = "/home/anair/temp/";

    public static final int KEY_LENGTH_1024 = 1024;
    public static final int KEY_LENGTH_576 = 576;
    public static final int RANDOM_PASSWORD_NUM = 24;
    public static final String KEY_STORE_FILE = KEY_CERT_PATH
            + "snbi.keystore.ks";
    public static final String KEY_STORE_PASSWORD = "snbitestkeystore";
    public static final String CERT_PASSWORD = "snbitestcertificate";

    public static final String KEY_STORE_ALIAS = "snbi.selfkey";
    public static final String KEY_STORE_CERT_ALIAS = "snbi.selfcert";

    public static final String SELF_SIGNED_CERT_FILE = KEY_CERT_PATH
            + "selfsignedsnbi.cert";
    public static final String HARDWARE_CERT_FILE = KEY_CERT_PATH
            + "hardware.txt";

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