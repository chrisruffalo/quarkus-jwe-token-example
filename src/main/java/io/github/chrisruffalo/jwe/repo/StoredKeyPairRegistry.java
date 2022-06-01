package io.github.chrisruffalo.jwe.repo;

import io.github.chrisruffalo.jwe.keypairs.KeyPairHandler;
import io.github.chrisruffalo.jwe.keypairs.KeyPairHandlerFactory;
import io.github.chrisruffalo.jwe.model.KeyType;
import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import org.jose4j.jwk.JsonWebKey;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.transaction.Transactional;
import java.security.KeyPair;
import java.util.Optional;
import java.util.UUID;

/**
 * This project uses the active record pattern but this class encapsulates key generation logic and has convenience
 * methods to keep dependencies from outside the data domain away from the active records.
 */
@ApplicationScoped
public class StoredKeyPairRegistry {

    @Inject
    KeyPairHandlerFactory handlerFactory;

    public Optional<KeyPair> fromStoredKeyPair(final StoredKeyPair storedKeyPair) {
        if (storedKeyPair == null) {
            return Optional.empty();
        }
        return handlerFactory.get(storedKeyPair.keyType).from(storedKeyPair.publicKey, storedKeyPair.privateKey);
    }

    @Transactional
    public Optional<KeyPair> resolveKeyPair(final String kid) {
        return StoredKeyPair.getKeyPairByKid(kid).filter(StoredKeyPair::isActive).flatMap(this::fromStoredKeyPair);
    }

    /**
     * Create a new key pair of the default type and persist it. This does not use the static panache methods
     * on the StoredKeyPair because the jwk there is type-agnostic while here a generator
     * is created and a specific key implementation is chosen.
     *
     * @return newly persisted instance of {@link StoredKeyPair}
     */
    public StoredKeyPair createNewKeyPair() {
        return createNewKeyPair(KeyType.DEFAULT);
    }

    /**
     * Create a new key pair of the selected type and persist it. This does not use the static panache methods
     * on the StoredKeyPair because the jwk there is type-agnostic while here a generator
     * is created and a specific key implementation is chosen.
     *
     * @param type the type of key to create
     * @return newly persisted instance of {@link StoredKeyPair}
     */
    @Transactional
    public StoredKeyPair createNewKeyPair(KeyType type) {
        // get the handler
        final KeyPairHandler handler = handlerFactory.get(type);

        // create pair
        final KeyPair pair = handler.generate();

        // create key id
        final String keyId = UUID.randomUUID().toString();

        // create entity object
        final StoredKeyPair serviceKeyPair = new StoredKeyPair();

        // turn into jwk if a web key was returned from the creator
        final Optional<JsonWebKey> webKey = handler.toWebKey(pair);
        webKey.ifPresent(key -> {
            key.setKeyId(keyId);
            serviceKeyPair.kid = key.getKeyId();
            serviceKeyPair.jwk = key.toJson();
        });

        // get key type and save encoded parts
        serviceKeyPair.keyType = type;
        serviceKeyPair.privateKey = pair.getPrivate().getEncoded();
        serviceKeyPair.publicKey = pair.getPublic().getEncoded();

        // set the (transient) original key pair for use without encoding/decoding within this context
        serviceKeyPair.originalPair = pair;

        // persist new key pair
        serviceKeyPair.persist();
        return serviceKeyPair;
    }
}
