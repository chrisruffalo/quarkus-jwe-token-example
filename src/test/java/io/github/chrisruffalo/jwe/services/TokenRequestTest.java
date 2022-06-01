package io.github.chrisruffalo.jwe.services;

import io.github.chrisruffalo.jwe.model.KeyType;
import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;

public abstract class TokenRequestTest {

    public static final String DEFAULT_CONSUMER = "submission";
    public static final String DEFAULT_SUBJECT = "test-subject";


    public String getToken() {
        return this.getToken(DEFAULT_CONSUMER, DEFAULT_SUBJECT, null);
    }

    public String getToken(final KeyType keyType) {
        return this.getToken(DEFAULT_CONSUMER, DEFAULT_SUBJECT, keyType);
    }

    public String getToken(final String consumer, final String subject, final KeyType keyType) {
        RequestSpecification specification = RestAssured.given();
        if (keyType != null) {
            specification = specification.queryParam("keyType", keyType.name().toLowerCase());
        }

        return specification.when()
                .pathParam("consumer", consumer)
                .pathParam("subject", subject)
                .get("/issuer/token/{consumer}/{subject}")
                .then()
                .statusCode(200)
                .extract()
                .response()
                .asPrettyString();
    }

}
