package io.github.chrisruffalo.jwe.jose;

import io.quarkus.arc.Priority;
import io.smallrye.jwt.auth.principal.*;
import org.jose4j.jwt.consumer.InvalidJwtException;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;
import javax.inject.Inject;

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