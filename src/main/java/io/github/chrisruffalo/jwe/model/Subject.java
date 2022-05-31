package io.github.chrisruffalo.jwe.model;

import javax.persistence.Entity;
import java.util.Optional;

/**
 * A subject has keys attached to it that are used by the issuing service to sign the JWT. The consumer uses these
 * keys later verify the key came from the issuing service.
 */
@Entity
public class Subject extends KeyPairEntity {

    public static Optional<Subject> findByName(final String name) {
        return find("name", name).firstResultOptional();
    }

}
