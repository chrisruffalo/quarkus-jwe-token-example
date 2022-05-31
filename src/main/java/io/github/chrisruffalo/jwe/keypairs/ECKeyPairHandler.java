package io.github.chrisruffalo.jwe.keypairs;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;

import javax.enterprise.context.ApplicationScoped;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

@ApplicationScoped
public class ECKeyPairHandler extends AbstractKeyPairHandler {

    private static final byte[] P256_HEAD = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE");

    @Override
    public String getInstanceName() {
        return "EC";
    }

    @Override
    protected String getSignatureAlgorithmHeaderValue() {
        return AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;
    }

    @Override
    protected String getEncryptionAlgorithmHeaderValue() {
        return KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW;
    }

    @Override
    protected KeySpec publicKeySpecFromBytes(byte[] bytes) {
        // this code doesn't seem to exactly work but finding out how to regenerate
        // the EC from encoded bytes is ... frustrating
        // the best/closest so far is from: https://stackoverflow.com/questions/30445997/loading-raw-64-byte-long-ecdsa-public-key-in-java
        byte[] encodedKey = new byte[P256_HEAD.length + bytes.length];
        System.arraycopy(P256_HEAD, 0, encodedKey, 0, P256_HEAD.length);
        System.arraycopy(bytes, 0, encodedKey, P256_HEAD.length, bytes.length);
        return new X509EncodedKeySpec(encodedKey);
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
            // no-op
        }
        return Optional.empty();
    }
}
