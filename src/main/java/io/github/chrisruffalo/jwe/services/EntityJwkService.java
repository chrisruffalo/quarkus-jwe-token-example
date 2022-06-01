package io.github.chrisruffalo.jwe.services;

import io.github.chrisruffalo.jwe.model.KeyPairEntity;
import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;

import java.util.List;

public abstract class EntityJwkService {

    protected JsonWebKeySet getJwks(final KeyPairEntity entity) {
        final JsonWebKeySet set = new JsonWebKeySet();
        final List<StoredKeyPair> pairs = entity.pairs;
        for(final StoredKeyPair skp : pairs) {
            if (!skp.isActive()) {
                continue;
            }
            try {
                set.addJsonWebKey(PublicJsonWebKey.Factory.newPublicJwk(skp.jwk));
            } catch (JoseException e) {
                throw new RuntimeException(e);
            }
        }
        return set;
    }

}
