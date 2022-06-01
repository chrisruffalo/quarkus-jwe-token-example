package io.github.chrisruffalo.jwe.model;

public enum KeyType {

    RSA,
    EC,
    EC256,
    EC384,
    EC512
    ;

    /**
     * Set the default key type here
     */
    public static final KeyType DEFAULT = KeyType.RSA;

}
