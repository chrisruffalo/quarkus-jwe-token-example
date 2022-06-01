package io.github.chrisruffalo.jwe.keypairs;

import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

public abstract class ECKeyPairHandler extends AbstractKeyPairHandler {

    protected abstract String getCurve();

    @Override
    public String getInstanceName() {
        return "EC";
    }

    @Override
    protected String getEncryptionAlgorithmHeaderValue() {
        return KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW;
    }

    @Override
    protected void customizeGenerator(KeyPairGenerator generator) throws InvalidAlgorithmParameterException {
        ECGenParameterSpec spec = new ECGenParameterSpec(this.getCurve());
        generator.initialize(spec);
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
    public Optional<JsonWebKey> toWebKey(KeyPair pair) {
        try {
            return Optional.of(new EllipticCurveJsonWebKey((ECPublicKey) pair.getPublic()));
        } catch (Exception ex) {
            logger.error("Could not create web key from pair", ex);
        }
        return Optional.empty();
    }
}
