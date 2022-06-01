package io.github.chrisruffalo.jwe.auth;


import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.smallrye.jwt.runtime.auth.JWTAuthMechanism;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import io.vertx.ext.web.RoutingContext;

import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;

/**
 * This class overrides the default {@link JWTAuthMechanism} to force the parsing of the JWT to take
 * place on a Worker thread. This allows DB calls (or something like HTTP requests to a JWKS endpoint)
 * to happen.
 */
@ApplicationScoped
@Alternative
@Priority(1)
public class CustomJWTAuthMechanism extends JWTAuthMechanism {

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        // override the authentication (parsing of the jwt) to happen in a worker thread and wait for it there
        // (there is probably a better way to do this than forcing a wait in the worker thread this way)
        return Uni.createFrom().item(super.authenticate(context, identityProviderManager)).emitOn(Infrastructure.getDefaultWorkerPool()).onItem().transform(uni -> uni.await().indefinitely());
    }

}
