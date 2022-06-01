package io.github.chrisruffalo.jwe.services.submission;

import io.github.chrisruffalo.jwe.model.Consumer;
import io.github.chrisruffalo.jwe.repo.StoredKeyPairRegistry;
import io.github.chrisruffalo.jwe.services.EntityJwkService;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;

import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Return the public keys available for encrypting a JWT intended to be
 * used by this service.
 */
@Path("/submission/jwks")
public class JwkService extends EntityJwkService {

    @Inject
    StoredKeyPairRegistry storedKeyPairRegistry;

    @GET
    @Transactional
    @Path("{consumer}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPublicKeys(@PathParam("consumer") final String consumerName) {
        final Consumer consumer = Consumer.findByName(consumerName).orElse(new Consumer());
        final JsonWebKeySet set = this.getJwks(consumer);
        return Response.ok(set.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)).build();
    }

}
