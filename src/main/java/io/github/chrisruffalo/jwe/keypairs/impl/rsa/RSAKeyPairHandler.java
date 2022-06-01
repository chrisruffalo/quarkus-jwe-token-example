package io.github.chrisruffalo.jwe.keypairs.impl.rsa;

import io.github.chrisruffalo.jwe.keypairs.AbstractKeyPairHandler;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

public abstract class RSAKeyPairHandler extends AbstractKeyPairHandler {

    protected abstract int getKeySize();

    @Override
    public String getInstanceName() {
        return "RSA";
    }

    @Override
    protected String getSignatureAlgorithmHeaderValue() {
        return AlgorithmIdentifiers.RSA_USING_SHA256;
    }

    @Override
    protected String getEncryptionAlgorithmHeaderValue() {
        return KeyManagementAlgorithmIdentifiers.RSA_OAEP_256;
    }

    @Override
    protected KeySpec publicKeySpecFromBytes(byte[] bytes) {
        return new X509EncodedKeySpec(bytes);
    }

    @Override
    protected KeySpec privateKeySpecFromBytes(byte[] bytes) {
        return new PKCS8EncodedKeySpec(bytes);
    }

    @Override
    protected void customizeGenerator(KeyPairGenerator generator) throws InvalidAlgorithmParameterException {
        super.customizeGenerator(generator);
        generator.initialize(this.getKeySize());
    }

    @Override
    public Optional<JsonWebKey> toWebKey(KeyPair pair) {
        try {
            return Optional.of(new RsaJsonWebKey((RSAPublicKey) pair.getPublic()));
        } catch (Exception ex) {
            logger.error("Could not create web key from pair", ex);
        }
        return Optional.empty();
    }
}
