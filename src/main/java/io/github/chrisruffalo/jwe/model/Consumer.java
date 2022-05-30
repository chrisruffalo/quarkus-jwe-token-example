package io.github.chrisruffalo.jwe.model;

import javax.persistence.Entity;
import java.util.Optional;

/**
 * A consumer is a registered consumer of the encrypted tokens. They register a public
 * key and that is used to encrypt the token used to identify the subject. The consumer
 * is also the audience of they key.
 */
@Entity
public class Consumer extends KeyPairEntity {

    public static Optional<Consumer> findByName(final String name) {
        return find("name", name).firstResultOptional();
    }

}
