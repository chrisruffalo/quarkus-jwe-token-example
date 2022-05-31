package io.github.chrisruffalo.jwe.services.submission;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Simulated secure endpoints that consume the encrypted/signed JWTs and use them for
 * RBAC.
 */
@Path("/submission")
public class SecuredService {

    @Inject
    @Claim(standard = Claims.sub)
    String subject;

    @Path("/status")
    @GET
    @RolesAllowed("Read")
    @Produces(MediaType.TEXT_PLAIN)
    public Response status() {
        return Response.ok("ok, " + subject).build();
    }

    @Path("/update")
    @POST
    @RolesAllowed("Write")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.TEXT_PLAIN)
    public Response update(final String body) {
        return Response.ok("thanks, " + subject).build();
    }

}
