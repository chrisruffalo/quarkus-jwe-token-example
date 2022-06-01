package io.github.chrisruffalo.jwe.services.submission;

import io.github.chrisruffalo.jwe.model.KeyType;
import io.github.chrisruffalo.jwe.services.TokenRequestTest;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.http.Header;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

@QuarkusTest
public class SubmissionServiceTest extends TokenRequestTest {

    public void roundTrip(final KeyType keyType) {
        final String jwt = this.getToken(keyType);
        this.callStatus(jwt);
    }

    public void callStatus(final String token) {
        this.callStatus(token, 200, "ok, " + DEFAULT_SUBJECT);
    }

    public void callStatus(final String token, final int expectedStatus, final String expectedMessage) {
        final String response = RestAssured.given()
                .header(new Header("Authorization", "Bearer " + token))
                .when().get("/submission/status")
                .then()
                .statusCode(expectedStatus)
                .extract()
                .response()
                .asPrettyString();

        Assertions.assertEquals(expectedMessage, response);
    }

    @Test
    public void roundTripDefault() {
        this.roundTrip(null);
    }

    @Test
    public void roundTripRSA() {
        this.roundTrip(KeyType.RSA);
    }

    @Test
    public void roundTripRSA2048() {
        this.roundTrip(KeyType.RSA2048);
    }

    @Test
    public void roundTripRSA4096() {
        this.roundTrip(KeyType.RSA4096);
    }

    @Test
    public void noToken() {
        this.callStatus("", 401, "");
    }

    @Test
    public void brokenToken() {
        final String jwt = this.getToken(KeyType.RSA);
        this.callStatus(jwt.substring(0, jwt.length() / 2), 401, "");
    }

    @Test
    public void roundTripEC() {
        this.roundTrip(KeyType.EC);
    }

    @Test
    public void roundTripEC256() {
        this.roundTrip(KeyType.EC256);
    }

    @Test
    public void roundTripEC384() {
        this.roundTrip(KeyType.EC384);
    }

    @Test
    public void roundTripEC521() {
        this.roundTrip(KeyType.EC521);
    }

}
