package io.github.chrisruffalo.jwe.jose;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;

@QuarkusTest
public class KeyResolverTest {

    @Inject
    KeyResolver resolver;

    @Test
    public void consumeRSA() throws InvalidJwtException, MalformedClaimException {
        final String jwt = RestAssured.given()
                .when().get("/issuer/token/submission/test")
                .then()
                .statusCode(200)
                .extract()
                .response()
                .asPrettyString();

        final JwtClaims claims = resolver.getConsumer().processToClaims(jwt);
        Assertions.assertEquals("submission", claims.getAudience().get(0));
        Assertions.assertEquals("test", claims.getSubject());
    }

    @Test
    public void consumeEC() throws InvalidJwtException, MalformedClaimException {
        final String jwt = RestAssured.given()
                .queryParam("keyType", "ec")
                .when().get("/issuer/token/submission/test")
                .then()
                .statusCode(200)
                .extract()
                .response()
                .asPrettyString();

        final JwtClaims claims = resolver.getConsumer().processToClaims(jwt);
        Assertions.assertEquals("submission", claims.getAudience().get(0));
        Assertions.assertEquals("test", claims.getSubject());
    }

    @Test
    public void consumeEC256() throws InvalidJwtException, MalformedClaimException {
        final String jwt = RestAssured.given()
                .queryParam("keyType", "ec256")
                .when().get("/issuer/token/submission/test")
                .then()
                .statusCode(200)
                .extract()
                .response()
                .asPrettyString();

        final JwtClaims claims = resolver.getConsumer().processToClaims(jwt);
        Assertions.assertEquals("submission", claims.getAudience().get(0));
        Assertions.assertEquals("test", claims.getSubject());
    }

    @Test
    public void consumeEC384() throws InvalidJwtException, MalformedClaimException {
        final String jwt = RestAssured.given()
                .queryParam("keyType", "ec384")
                .when().get("/issuer/token/submission/test")
                .then()
                .statusCode(200)
                .extract()
                .response()
                .asPrettyString();

        final JwtClaims claims = resolver.getConsumer().processToClaims(jwt);
        Assertions.assertEquals("submission", claims.getAudience().get(0));
        Assertions.assertEquals("test", claims.getSubject());
    }

    @Test
    public void consumeEC521() throws InvalidJwtException, MalformedClaimException {
        final String jwt = RestAssured.given()
                .queryParam("keyType", "ec521")
                .when().get("/issuer/token/submission/test")
                .then()
                .statusCode(200)
                .extract()
                .response()
                .asPrettyString();

        final JwtClaims claims = resolver.getConsumer().processToClaims(jwt);
        Assertions.assertEquals("submission", claims.getAudience().get(0));
        Assertions.assertEquals("test", claims.getSubject());
    }

}
