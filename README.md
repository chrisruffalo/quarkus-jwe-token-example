# Quarkus JWE Example

## Description
This is an example project that shows interaction between mutual trust in two services. The two services are packaged
together but are logically distinct. The issuer and consumer (audience) interact only through their published keys 
and the JWT (JWS in JWE) token.

## Concept of Operations
- The issuer service (`/issuer/token`) issues tokens that can be used by a consumer by a subject. The path parameters
  of the service (`/issuer/token/{consumer}/{subject}`) drive the creation of the JWT. In "real life" the token service
  would be behind a human UI and would be separately authenticated to allow users to create tokens.
- The consumer services (`/submission/*`) require a token issued by the issuer. They are encrypted with an active consumer
  key and signed with a key that is specific to the subject and unique to the token itself.

The issuer creates a claims package that is first signed by the issuer private key to make a JWS. Then the intended 
consumer public key is used to encrypt the JWS to make a JWE. The consumer can use its own private key to decrypt the JWE
to make a JWS and then it can get the issuer public key to verify the issuer.

## What does this demo... demonstrate?

- Active records
  - See [the model package](src/main/java/io/github/chrisruffalo/jwe/model) for classes that implement the Panache active record pattern
- JWE/JWS/JWT generation:
  - See [TokenService](src/main/java/io/github/chrisruffalo/jwe/services/issuer/TokenService.java) to see how a token is created from keys
- JWE/JWS/JWT parsing:
  - See [KeyResolver](src/main/java/io/github/chrisruffalo/jwe/auth/KeyResolver.java) for a custom JWTConsumer.
  - See [TokenServiceTest](src/test/java/io/github/chrisruffalo/jwe/services/issuer/TokenServiceTest.java) for manual JWE/JWS parsing
- JWKS Creation
  - See [issuer JwkService](src/main/java/io/github/chrisruffalo/jwe/services/issuer/JwkService.java) and the [consumer JwkService](src/main/java/io/github/chrisruffalo/jwe/services/submission/JwkService.java) for how to create JWKS for encryption/verification
- Service secured by JWT claim groups
  - See [SubmissionService](src/main/java/io/github/chrisruffalo/jwe/services/submission/SubmissionService.java) to see the annotations and claim usage
- Customization of Quarkus JWT Parsing
  - See [CustomJWTAuthMechanism](src/main/java/io/github/chrisruffalo/jwe/auth/CustomJWTAuthMechanism.java) for how the JWT parsing was pushed to a worker thread
  - See [CustomJWTCallerPrincipalFactory](src/main/java/io/github/chrisruffalo/jwe/auth/CustomJWTCallerPrincipalFactory.java) for how the JWT parsing was customized to use a custom JWT consumer (that can resolve keys at runtime)
- BCFIPS Integration
  - See [BCProvider](src/main/java/io/github/chrisruffalo/jwe/crypto/BCProvider.java) for creating a BCFIPS instance with low entropy requirements
- Quartz Jobs
  - See [ExpiresKeysTask](src/main/java/io/github/chrisruffalo/jwe/tasks/ExpireKeysTask.java) for expiring keys that are expired but active in the DB

## Requirements
- Local development requires Docker for use of [TestContainers](https://www.testcontainers.org/)
- There is no "production" deployment of this because it is intended as a proof of concept/demo only 

## Running
The easiest way to run is `mvn quarkus:test` and then use the provided `test.sh` test script. The test script
requests a token and then uses it against the submission endpoint.
