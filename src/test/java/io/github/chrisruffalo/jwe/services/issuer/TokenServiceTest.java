package io.github.chrisruffalo.jwe.services.issuer;

import io.github.chrisruffalo.jwe.model.KeyType;
import io.github.chrisruffalo.jwe.repo.StoredKeyPairRegistry;
import io.github.chrisruffalo.jwe.services.TokenRequestTest;
import io.quarkus.test.junit.QuarkusTest;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

@QuarkusTest
public class TokenServiceTest extends TokenRequestTest {

    @Inject
    StoredKeyPairRegistry storedKeyPairRegistry;

    /**
     * Create and verify the token of a given type
     *
     * @param type to test
     */
    public void createAndVerifyToken(final KeyType type) {
        try {
            final String jwe = this.getToken(type);
            Assertions.assertNotNull(jwe);
            Assertions.assertTrue(jwe.length() > 0);

            // parse and ensure type
            final JsonWebEncryption jsonWebEncryption = new JsonWebEncryption();
            jsonWebEncryption.setCompactSerialization(jwe);
            final Optional<KeyPair> decryptionKeyPair = storedKeyPairRegistry.resolveKeyPair(jsonWebEncryption.getKeyIdHeaderValue());
            Assertions.assertTrue(decryptionKeyPair.isPresent());
            if(type != null && type.name().toLowerCase().startsWith("ec")) {
                Assertions.assertInstanceOf(ECPublicKey.class, decryptionKeyPair.get().getPublic());
                Assertions.assertInstanceOf(ECPrivateKey.class, decryptionKeyPair.get().getPrivate());
            } else {
                Assertions.assertInstanceOf(RSAPublicKey.class, decryptionKeyPair.get().getPublic());
                Assertions.assertInstanceOf(RSAPrivateKey.class, decryptionKeyPair.get().getPrivate());
            }
            jsonWebEncryption.setKey(decryptionKeyPair.get().getPrivate());

            final String decryptedPayload = jsonWebEncryption.getPayload();
            Assertions.assertNotNull(decryptedPayload);

            // parse and ensure signed
            final JsonWebSignature jsonWebSignature = new JsonWebSignature();
            jsonWebSignature.setCompactSerialization(decryptedPayload);
            final Optional<KeyPair> signingKeyPair = storedKeyPairRegistry.resolveKeyPair(jsonWebSignature.getKeyIdHeaderValue());
            Assertions.assertTrue(signingKeyPair.isPresent());
            if(type != null && type.name().toLowerCase().startsWith("ec")) {
                Assertions.assertInstanceOf(ECPublicKey.class, signingKeyPair.get().getPublic());
                Assertions.assertInstanceOf(ECPrivateKey.class, signingKeyPair.get().getPrivate());
            } else {
                Assertions.assertInstanceOf(RSAPublicKey.class, signingKeyPair.get().getPublic());
                Assertions.assertInstanceOf(RSAPrivateKey.class, signingKeyPair.get().getPrivate());
            }
            jsonWebSignature.setKey(signingKeyPair.get().getPublic());

            final String jwt = jsonWebSignature.getPayload();
            final JwtClaims claims = JwtClaims.parse(jwt);

            // ensure claims
            Assertions.assertEquals(jsonWebEncryption.getHeader("sub"), claims.getSubject());
        } catch (Exception ex) {
            Assertions.fail(ex);
        }
    }

    @Test
    public void createAndVerifyDefault() {
        this.createAndVerifyToken(null);
    }

    @Test
    public void createAndVerifyRSA() {
        this.createAndVerifyToken(KeyType.RSA);
    }

    @Test
    public void createAndVerifyRSA2048() {
        this.createAndVerifyToken(KeyType.RSA2048);
    }

    @Test
    public void createAndVerifyRSA4096() {
        this.createAndVerifyToken(KeyType.RSA4096);
    }

    @Test
    public void createAndVerifyEC() {
        this.createAndVerifyToken(KeyType.EC);
    }

    @Test
    public void createAndVerifyEC256() {
        this.createAndVerifyToken(KeyType.EC256);
    }

    @Test
    public void createAndVerifyEC384() {
        this.createAndVerifyToken(KeyType.EC384);
    }

    @Test
    public void createAndVerifyEC521() {
        this.createAndVerifyToken(KeyType.EC521);
    }

}
