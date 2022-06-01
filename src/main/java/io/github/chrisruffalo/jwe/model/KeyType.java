package io.github.chrisruffalo.jwe.model;

/**
 * Represents all the supported key generation/encryption/signing implementations.
 */
public enum KeyType {

    RSA,
    RSA2048,
    RSA4096,
    EC,
    EC256,
    EC384,
    EC521
    ;

    /**
     * Set the default key type here
     */
    public static final KeyType DEFAULT = KeyType.RSA;

}
