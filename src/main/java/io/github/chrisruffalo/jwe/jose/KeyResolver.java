package io.github.chrisruffalo.jwe.jose;

import io.github.chrisruffalo.jwe.repo.StoredKeyPairRegistry;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import javax.annotation.PostConstruct;
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

    private JwtConsumer consumer;

    @PostConstruct
    public void init() {
        this.consumer = new JwtConsumerBuilder()
                .setAllowedClockSkewInSeconds(5)
                .setRequireExpirationTime()
                .setRequireSubject()
                .setRequireJwtId()
                .setRequireIssuedAt()
                // in a real application this would set the audience
                // to be the consuming application.
                .setSkipDefaultAudienceValidation()
                .setDecryptionKeyResolver(this)
                .setVerificationKeyResolver(this)
                .build();
    }

    public JwtConsumer getConsumer() {
        return this.consumer;
    }

    @Override
    public Key resolveKey(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        return storedKeyPairRegistry.resolveKeyPair(jwe.getKeyIdHeaderValue()).orElseThrow(() -> new UnresolvableKeyException("Cannot resolve private key")).getPrivate();
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        return storedKeyPairRegistry.resolveKeyPair(jws.getKeyIdHeaderValue()).orElseThrow(() -> new UnresolvableKeyException("Cannot resolve public key")).getPublic();
    }
}
