package io.github.chrisruffalo.jwe.jose;

import io.github.chrisruffalo.jwe.repo.StoredKeyPairRegistry;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.Key;
import java.util.List;

/**
 * Allows JWE/JWS keys to be resolved, by id, from the database
 */
@ApplicationScoped
public class KeyResolver implements DecryptionKeyResolver, VerificationKeyResolver {

    @Inject
    StoredKeyPairRegistry storedKeyPairRegistry;

    @Override
    public Key resolveKey(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        return storedKeyPairRegistry.resolveKeyPair(jwe.getKeyIdHeaderValue()).orElseThrow(() -> new UnresolvableKeyException("")).getPrivate();
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        return storedKeyPairRegistry.resolveKeyPair(jws.getKeyIdHeaderValue()).orElseThrow(() -> new UnresolvableKeyException("")).getPublic();
    }
}
