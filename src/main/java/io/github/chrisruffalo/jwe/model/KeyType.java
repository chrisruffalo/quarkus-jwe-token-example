package io.github.chrisruffalo.jwe.model;

public enum KeyType {

    RSA,
    EC
    ;

    /**
     * Set the default key type here
     */
    public static final KeyType DEFAULT = KeyType.RSA;

}
