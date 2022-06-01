package io.github.chrisruffalo.jwe.jose;


import io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TokenAuthenticationRequest;
import io.quarkus.smallrye.jwt.runtime.auth.JWTAuthMechanism;
import io.quarkus.smallrye.jwt.runtime.auth.JsonWebTokenCredential;
import io.smallrye.jwt.auth.AbstractBearerTokenExtractor;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.unchecked.Unchecked;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.web.RoutingContext;
import org.jboss.logging.Logger;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;
import javax.inject.Inject;
import java.util.Optional;
import java.util.Set;

/**
 * This was implemented instead of creating an implementation of {@link io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory}
 * because that class could not be made to block for the results from the key resolver. This class, returning a Uni<> seemed like
 * a better choice.
 */
@ApplicationScoped
@Alternative
@Priority(1)
public class CustomJWTAuthMechanism extends JWTAuthMechanism {

    @Inject
    JWTAuthContextInfo authContextInfo;

    @Inject
    KeyResolver resolver;

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        String jwtToken = new VertxBearerTokenExtractor(authContextInfo, context).getBearerToken();

        if (jwtToken != null) {
            return Uni.createFrom().item(jwtToken)
                .onItem().transform(Unchecked.function(token -> {
                    // this is the actual consumer that creates the JWT from the nested JSE inside
                    // the JWE. This allows it to be done all in one pass. I had another implementation
                    // where it was done in phases but the reactive logic of it was a bit much and I
                    // haven't learned how to fan out and merge back in a way that makes sense yet.
                    return resolver.getConsumer().processToClaims(token);
                }))
                .onFailure(failure -> false)
                .recoverWithItem(new JwtClaims())
                .onItem().transform(JwtClaims::toJson)
                .onItem().transformToUni(jsonClaims -> identityProviderManager.authenticate(new TokenAuthenticationRequest(new JsonWebTokenCredential(jsonClaims))));
        }
        return Uni.createFrom().optional(Optional.empty());
    }

    /**
     * This is copied from {@link JWTAuthMechanism} because that is established code already being used for this
     * purpose but it is not accessible to child classes.
     */
    private static class VertxBearerTokenExtractor extends AbstractBearerTokenExtractor {
        private final RoutingContext httpExchange;

        VertxBearerTokenExtractor(JWTAuthContextInfo authContextInfo, RoutingContext exchange) {
            super(authContextInfo);
            this.httpExchange = exchange;
        }

        @Override
        protected String getHeaderValue(String headerName) {
            return httpExchange.request().headers().get(headerName);
        }

        @Override
        protected String getCookieValue(String cookieName) {
            String cookieHeader = httpExchange.request().headers().get(HttpHeaders.COOKIE);

            if (cookieHeader != null && httpExchange.cookieCount() == 0) {
                Set<io.netty.handler.codec.http.cookie.Cookie> nettyCookies = ServerCookieDecoder.STRICT.decode(cookieHeader);
                for (io.netty.handler.codec.http.cookie.Cookie cookie : nettyCookies) {
                    if (cookie.name().equals(cookieName)) {
                        return cookie.value();
                    }
                }
            }
            Cookie cookie = httpExchange.getCookie(cookieName);
            return cookie != null ? cookie.getValue() : null;
        }
    }
}
