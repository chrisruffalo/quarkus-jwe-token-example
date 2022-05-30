package io.github.chrisruffalo.jwe.repo;

import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class StoredKeyPairRegistry {

    public static int EXPIRES_MINUTES = 10;

    private KeyPairGenerator generator;

    private KeyFactory factory;

    @PostConstruct
    public void init() {
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            factory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<KeyPair> fromEncoded(final byte[] publicKey, final byte[] privateKey) {
        try {
            return Optional.of(new KeyPair(
                factory.generatePublic(new X509EncodedKeySpec(publicKey)),
                factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey))
            ));
        } catch (InvalidKeySpecException e) {
            return Optional.empty();
        }
    }

    public Optional<KeyPair> fromStoredKeyPair(final StoredKeyPair storedKeyPair) {
        if (storedKeyPair == null) {
            return Optional.empty();
        }
        return fromEncoded(storedKeyPair.publicKey, storedKeyPair.privateKey);
    }

    /**
     * Create a new key pair and persist it. This does not use the static panache methods
     * on the StoredKeyPair because the jwk there is type-agnostic while here a generator
     * is created and a specific key implementation is chosen.
     *
     * @return newly persisted instance of {@link StoredKeyPair}
     */
    public StoredKeyPair createNewKeyPair() {
        // create pair
        final KeyPair pair = generator.generateKeyPair();

        // set expiration
        final Calendar exp = Calendar.getInstance();
        exp.add(Calendar.MINUTE, EXPIRES_MINUTES);

        // create key id
        final String keyId = UUID.randomUUID().toString();

        // turn into jwk
        final JsonWebKey webKey = new RsaJsonWebKey((RSAPublicKey)pair.getPublic());
        webKey.setKeyId(keyId);

        // create entity object
        StoredKeyPair serviceKeyPair = new StoredKeyPair();
        serviceKeyPair.kid = webKey.getKeyId();
        serviceKeyPair.jwk = webKey.toJson();
        serviceKeyPair.expires = exp.getTime();
        serviceKeyPair.privateKey = pair.getPrivate().getEncoded();
        serviceKeyPair.publicKey = pair.getPublic().getEncoded();

        // persist new key pair
        serviceKeyPair.persist();
        return serviceKeyPair;
    }
}
