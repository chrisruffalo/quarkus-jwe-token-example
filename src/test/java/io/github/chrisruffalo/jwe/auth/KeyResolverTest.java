package io.github.chrisruffalo.jwe.auth;

import io.github.chrisruffalo.jwe.model.KeyType;
import io.github.chrisruffalo.jwe.services.TokenRequestTest;
import io.quarkus.test.junit.QuarkusTest;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;

/**
 * While this test mimics a lot of the SubmissionServiceTest it is about raw JWT parsing
 * and the JWTConsumer configuration. This helps diagnose unexplained 401 errors when
 * accessing endpoints.
 */
@QuarkusTest
public class KeyResolverTest extends TokenRequestTest {

    @Inject
    KeyResolver resolver;

    private void check(final KeyType keyType) {
        try {
            final String jwt = getToken(keyType);
            final JwtClaims claims = resolver.getConsumer().processToClaims(jwt);
            Assertions.assertEquals(TokenRequestTest.DEFAULT_CONSUMER, claims.getAudience().get(0));
            Assertions.assertEquals(TokenRequestTest.DEFAULT_SUBJECT, claims.getSubject());
        } catch (Exception e) {
            Assertions.fail(e);
        }
    }

    @Test
    public void consumeDefault() {
        this.check(null);
    }

    @Test
    public void consumeRSA() {
        this.check(KeyType.RSA);
    }

    @Test
    public void consumeRSA2048() {
        this.check(KeyType.RSA2048);
    }

    @Test
    public void consumeRSA4096() {
        this.check(KeyType.RSA4096);
    }

    @Test
    public void consumeEC() {
        this.check(KeyType.EC);
    }

    @Test
    public void consumeEC256() {
        this.check(KeyType.EC256);
    }

    @Test
    public void consumeEC384() {
        this.check(KeyType.EC384);
    }

    @Test
    public void consumeEC521() {
        this.check(KeyType.EC521);
    }
}
