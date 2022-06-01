package io.github.chrisruffalo.jwe.keypairs;

import io.github.chrisruffalo.jwe.exception.StoredKeyToKeyPairException;
import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import org.jboss.logging.Logger;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Optional;

public abstract class AbstractKeyPairHandler implements KeyPairHandler {

    @Inject
    Logger logger;

    private KeyPairGenerator generator;

    private KeyFactory factory;

    protected String getProviderName() {
        return "BCFIPS";
    }

    protected abstract String getInstanceName();

    protected abstract KeySpec publicKeySpecFromBytes(final byte[] bytes);

    protected abstract KeySpec privateKeySpecFromBytes(final byte[] bytes);

    protected abstract String getSignatureAlgorithmHeaderValue();

    protected abstract String getEncryptionAlgorithmHeaderValue();

    protected Logger logger() {
        return this.logger;
    }

    protected String getEncryptionMethodHeaderParameter() {
        return ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512;
    }

    protected void customizeGenerator(final KeyPairGenerator generator) throws InvalidAlgorithmParameterException {
        // no-op by default
    }

    @PostConstruct
    public void init() {
        try {
            final String providerName = this.getProviderName();

            // create a new generator from the default provider
            generator = KeyPairGenerator.getInstance(this.getInstanceName(), providerName);
            this.customizeGenerator(generator);

            // create a new factory from the default provider
            factory = KeyFactory.getInstance(this.getInstanceName(), providerName);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyPair generate() {
        return this.getGenerator().generateKeyPair();
    }

    @Override
    public Optional<KeyPair> from(final StoredKeyPair storedKeyPair) {
        if (storedKeyPair == null) {
            return Optional.empty();
        }
        return this.from(storedKeyPair.publicKey, storedKeyPair.privateKey);
    }

    @Override
    public Optional<KeyPair> from(byte[] publicKey, byte[] privateKey) {
        try {
            return Optional.of(new KeyPair(
                this.getFactory().generatePublic(publicKeySpecFromBytes(publicKey)),
                this.getFactory().generatePrivate(privateKeySpecFromBytes(privateKey))
            ));
        } catch (InvalidKeySpecException e) {
            logger.error("Could not create key pair from bytes", e);
            return Optional.empty();
        }
    }

    @Override
    public void configureSignature(JsonWebSignature signature, StoredKeyPair storedKeyPair) throws StoredKeyToKeyPairException {
        signature.setKeyIdHeaderValue(storedKeyPair.kid);
        if(storedKeyPair.originalPair != null) {
            signature.setKey(storedKeyPair.originalPair.getPrivate());
        } else {
            signature.setKey(this.from(storedKeyPair).orElseThrow(StoredKeyToKeyPairException::new).getPrivate());   // signed with the private key from the producer to ensure
                                                                                                                       // that we can verify that it came from only the issuer
        }
        signature.setAlgorithmHeaderValue(this.getSignatureAlgorithmHeaderValue());
    }

    @Override
    public void configureEncryption(JsonWebEncryption encrypted, StoredKeyPair storedKeyPair) throws StoredKeyToKeyPairException {
        encrypted.setKeyIdHeaderValue(storedKeyPair.kid);
        if(storedKeyPair.originalPair != null) {
            encrypted.setKey(storedKeyPair.originalPair.getPublic());
        } else {
            encrypted.setKey(this.from(storedKeyPair).orElseThrow(StoredKeyToKeyPairException::new).getPublic());
        }
        encrypted.setAlgorithmHeaderValue(this.getEncryptionAlgorithmHeaderValue());
        encrypted.setEncryptionMethodHeaderParameter(this.getEncryptionMethodHeaderParameter());
    }

    public KeyPairGenerator getGenerator() {
        return generator;
    }

    public KeyFactory getFactory() {
        return factory;
    }
}
