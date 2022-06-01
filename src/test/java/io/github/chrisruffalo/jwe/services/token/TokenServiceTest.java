package io.github.chrisruffalo.jwe.services.token;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

@QuarkusTest
public class TokenServiceTest {

    @Test
    public void createRSAToken() {
        final String responseBody = RestAssured.given()
            .when().get("/issuer/token/submission/test")
            .then()
                .statusCode(200)
                .extract()
                .response()
                .asPrettyString();

        // now we have the token
        Assertions.assertNotNull(responseBody);
        Assertions.assertFalse(responseBody.isEmpty());
    }

    @Test
    public void createECToken() {
        final String responseBody = RestAssured.given()
                .queryParam("keyType", "ec")
                .when().get("/issuer/token/submission/test")
                .then()
                .statusCode(200)
                .extract()
                .response()
                .asPrettyString();

        // now we have the token
        Assertions.assertNotNull(responseBody);
        Assertions.assertFalse(responseBody.isEmpty());
    }

}
