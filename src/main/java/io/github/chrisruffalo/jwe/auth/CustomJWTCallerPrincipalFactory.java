package io.github.chrisruffalo.jwe.auth;

import io.quarkus.arc.Priority;
import io.smallrye.jwt.auth.principal.*;
import org.jose4j.jwt.consumer.InvalidJwtException;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;
import javax.inject.Inject;

/**
 * Allows the usage of custom logic when it comes to parsing a provided JWT to a claims object. This
 * class uses the JWTConsumer in the Key Resolver to produce a key that is parsed within the PK
 * infrastructure/ecosystem of these two services.
 */
@ApplicationScoped
@Alternative
@Priority(1)
public class CustomJWTCallerPrincipalFactory extends JWTCallerPrincipalFactory {

    @Inject
    KeyResolver keyResolver;

    @Override
    public JWTCallerPrincipal parse(String token, JWTAuthContextInfo authContextInfo) throws ParseException {
        try {
            return new DefaultJWTCallerPrincipal(keyResolver.getConsumer().processToClaims(token));
        } catch (InvalidJwtException ex) {
            throw new ParseException(ex.getMessage());
        }
    }
}