package io.github.chrisruffalo.jwe.keypairs;

import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;

import javax.enterprise.context.ApplicationScoped;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

@ApplicationScoped
public class RSAKeyPairHandler extends AbstractKeyPairHandler {

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
    public Optional<JsonWebKey> toWebKey(KeyPair pair) {
        try {
            return Optional.of(new RsaJsonWebKey((RSAPublicKey) pair.getPublic()));
        } catch (Exception ex) {
            logger.error("Could not create web key from pair", ex);
        }
        return Optional.empty();
    }
}
