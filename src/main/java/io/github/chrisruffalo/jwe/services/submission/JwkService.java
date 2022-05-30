package io.github.chrisruffalo.jwe.services.submission;

import io.github.chrisruffalo.jwe.model.Consumer;
import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import io.github.chrisruffalo.jwe.repo.StoredKeyPairRegistry;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;

import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Optional;

@Path("/submission/jwks")
public class JwkService {

    @Inject
    StoredKeyPairRegistry storedKeyPairRegistry;

    @GET
    @Transactional
    @Path("{consumer}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPublicKeys(final String consumer) {
        final JsonWebKeySet set = new JsonWebKeySet();
        Consumer.findByName(consumer).ifPresent(c -> {
            Optional<StoredKeyPair> active = c.getFirstActiveKeyPair();
            if (active.isPresent()) {
                try {
                    set.addJsonWebKey(PublicJsonWebKey.Factory.newPublicJwk(active.get().jwk));
                } catch (JoseException e) {
                    // log?
                }
            }
        });
        return Response.ok(set.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)).build();
    }

}
