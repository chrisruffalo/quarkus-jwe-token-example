package io.github.chrisruffalo.jwe.services.token;

import io.github.chrisruffalo.jwe.exception.StoredKeyToKeyPairException;
import io.github.chrisruffalo.jwe.model.Consumer;
import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import io.github.chrisruffalo.jwe.model.Subject;
import io.github.chrisruffalo.jwe.repo.StoredKeyPairRegistry;
import org.jboss.logging.Logger;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;

import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Calendar;

/**
 * This creates a token for a given subject (machine/service/human) to interact with a consumer (like
 * the submission service). The relevant keys are created and stored for reuse (until being revoked).
 */
@Path("/issuer/token")
public class TokenService {

    private static final String ISSUER = "token-service";

    @Inject
    Logger logger;

    @Inject
    StoredKeyPairRegistry keyPairRegistry;

    @Transactional
    @Path("/{consumer}/{subject}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response generate(@PathParam("consumer") final String consumerName, @PathParam("subject") final String subjectName) {
        if (subjectName == null || subjectName.isEmpty()) {
            return Response.serverError().build();
        }

        // get existing subject or create it if it does not exist
        final Subject subject = Subject.findByName(subjectName).orElseGet(() -> {
            final Subject newSubject = new Subject();
            newSubject.name = subjectName;
            newSubject.persist();
            return newSubject;
        });

        final Consumer consumer = Consumer.findByName(consumerName).orElseGet(() -> {
            final Consumer newConsumer = new Consumer();
            newConsumer.name = consumerName;
            newConsumer.persist();
            return newConsumer;
        });

        try {
            final Calendar future = Calendar.getInstance();
            future.add(Calendar.YEAR, 1);

            final JwtClaims claims = new JwtClaims();
            claims.setGeneratedJwtId();
            claims.setIssuedAtToNow();
            claims.setExpirationTime(NumericDate.fromMilliseconds(future.getTimeInMillis()));
            claims.setSubject(subjectName);
            claims.setIssuer(ISSUER);
            claims.setAudience(consumerName);
            claims.setStringListClaim("groups", "Read", "Write");

            // each token is signed by its own key. this means that a key can be revoked/deactivated which
            // will make it impossible to validate the key. this results in cryptographically revoked keys
            // rather than a logical revoke which could be error-prone.
            final StoredKeyPair signingPair = keyPairRegistry.createNewKeyPair();
            signingPair.active = true;
            subject.pairs.add(signingPair);

            // create signed payload for jwe
            final JsonWebSignature toSign = new JsonWebSignature();
            toSign.setPayload(claims.toJson());
            toSign.setKey(keyPairRegistry.fromStoredKeyPair(signingPair).orElseThrow(StoredKeyToKeyPairException::new).getPrivate());   // signed with the private key from the producer to ensure
                                                                                                                                        // that we can verify that it came from only the issuer
            toSign.setKeyIdHeaderValue(signingPair.jwk);
            toSign.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
            final String signedPayload = toSign.getCompactSerialization();

            // when it comes to the consuming public key we can choose an already active key. this allows the consumer
            // to rotate keys while still being able to support decryption on its side.
            final StoredKeyPair consumerPair = consumer.getFirstActiveKeyPair().orElseGet(() -> {
                StoredKeyPair pair = keyPairRegistry.createNewKeyPair();
                pair.active = true;
                consumer.pairs.add(pair);
                return pair;
            });

            final JsonWebEncryption toEncrypt = new JsonWebEncryption();
            // copy _some_ claims to the header so that users can introspect the token but these claims
            // will _never_ be used by the application. these are only to allow partially transparent
            // encrypted tokens to simplify management on the client side
            toEncrypt.setHeader("exp", claims.getExpirationTime().getValueInMillis());
            toEncrypt.setHeader("sub", claims.getSubject());
            toEncrypt.setKey(keyPairRegistry.fromStoredKeyPair(consumerPair).orElseThrow(StoredKeyToKeyPairException::new).getPublic()); // encrypted by the consumer's public key so only it can decrypt
            toEncrypt.setKeyIdHeaderValue(consumerPair.kid);
            toEncrypt.setContentTypeHeaderValue("JWT");
            toEncrypt.setPayload(signedPayload);
            toEncrypt.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
            toEncrypt.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);

            // return encrypted object
            final String encodedToken = toEncrypt.getCompactSerialization();

            return Response.ok(encodedToken).build();
        } catch (JoseException | MalformedClaimException | StoredKeyToKeyPairException e) {
            logger.error("Could not create token", e);
            return Response.serverError().build();
        }
    }


}
