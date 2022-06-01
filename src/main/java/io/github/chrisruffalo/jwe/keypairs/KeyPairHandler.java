package io.github.chrisruffalo.jwe.keypairs;

import io.github.chrisruffalo.jwe.exception.StoredKeyToKeyPairException;
import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;

import java.security.KeyPair;
import java.util.Optional;

/**
 * An interface for doing all the necessary key creation and handling for a particular
 * key type (like: RSA, RSA2048, EC384, etc).
 */
public interface KeyPairHandler {

    /**
     * Generate a new key pair
     *
     * @return a newly generated key pair
     */
    KeyPair generate();

    /**
     * From a stored key pair create the keypair instance
     *
     * @return a key pair
     */
    Optional<KeyPair> from(final StoredKeyPair storedKeyPair);

    /**
     * Restore a serialized byte[] key pair to being a key pair object.
     *
     * @param publicKey  the public key to use
     * @param privateKey the private key to use
     * @return a key pair instance
     */
    Optional<KeyPair> from(final byte[] publicKey, final byte[] privateKey);

    /**
     * Create a (public only) JSON web key from the given key pair
     *
     * @param pair the pair to use
     * @return the json web key version of the pair
     */
    Optional<JsonWebKey> toWebKey(final KeyPair pair);

    /**
     * Given a signature object and a stored key pair, configure the signature for use
     *
     * @param signature     the signature
     * @param storedKeyPair the stored key pair
     */
    void configureSignature(final JsonWebSignature signature, final StoredKeyPair storedKeyPair) throws StoredKeyToKeyPairException;

    /**
     * Given an encryption object and a stored key pair, configure encryption for use
     *
     * @param signature     the signature
     * @param storedKeyPair the stored key pair
     */
    void configureEncryption(final JsonWebEncryption signature, final StoredKeyPair storedKeyPair) throws StoredKeyToKeyPairException;
}
