package io.github.chrisruffalo.jwe.jose;

import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import io.github.chrisruffalo.jwe.repo.StoredKeyPairRegistry;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import java.security.Key;
import java.security.KeyPair;
import java.util.List;
import java.util.Optional;

@RequestScoped
public class KeyResolver implements DecryptionKeyResolver, VerificationKeyResolver {

    @Inject
    StoredKeyPairRegistry storedKeyPairRegistry;

    public Optional<KeyPair> resolveKeyPair(final String kid) {
        return StoredKeyPair.getKeyPairByKid(kid).flatMap((pair) -> storedKeyPairRegistry.fromStoredKeyPair(pair));
    }

    @Override
    public Key resolveKey(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        return resolveKeyPair(jwe.getKeyIdHeaderValue()).orElseThrow(() -> new UnresolvableKeyException("")).getPrivate();
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        return resolveKeyPair(jws.getKeyIdHeaderValue()).orElseThrow(() -> new UnresolvableKeyException("")).getPublic();
    }
}
