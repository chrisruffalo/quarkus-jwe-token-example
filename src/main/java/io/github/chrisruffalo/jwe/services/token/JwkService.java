package io.github.chrisruffalo.jwe.services.token;

import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import io.github.chrisruffalo.jwe.model.Subject;
import org.jboss.logging.Logger;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;

import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * An endpoint that provides consumers with the ability to verify the signature of a subject
 * from the issuer. A consumer would call this endpoint to get the up-to-date list of JWKS for
 * a specific subject when that subject contacts the consuming service. If the public key is not
 * provided/available/listed then the key is no longer active.
 */
@Path("/issuer/jwks")
public class JwkService {

    @Inject
    Logger logger;

    @GET
    @Transactional
    @Path("{subject}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPublicKeys(@PathParam("subject") final String subjectName) {
        final JsonWebKeySet set = new JsonWebKeySet();
        final Subject subject = Subject.findByName(subjectName).orElse(new Subject());
        final List<StoredKeyPair> pairs = subject.pairs;
        for(final StoredKeyPair skp : pairs) {
            if (!skp.isActive()) {
                continue;
            }
            try {
                set.addJsonWebKey(PublicJsonWebKey.Factory.newPublicJwk(skp.jwk));
            } catch (JoseException e) {
                throw new RuntimeException(e);
            }
        }
        return Response.ok(set.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)).build();
    }
}
