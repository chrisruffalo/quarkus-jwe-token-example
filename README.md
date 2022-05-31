# Quarkus JWE Example

## Description
This is an example project that shows interaction between mutual trust in two services. The two services are packaged
together but are logically distinct.

## Concept of Operations
- The issuer service (`/issuer/token`) issues tokens that can be used by a consumer by a subject. The path parameters
  of the service (`/issuer/token/{consumer}/{subject}`) drive the creation of the JWT. In "real life" the token service
  would be behind a human UI and would be separately authenticated to allow users to create tokens.
- The consumer services (`/submission/*`) require a token issued by the issuer. They are encrypted with an active consumer
  key and signed with a key that is specific to the subject and unique to the token itself.

## Running
The easiest way to run is `mvn quarkus:test` and then use the provided `test.sh` test script. The test script
requests a token and then uses it against the submission endpoint.