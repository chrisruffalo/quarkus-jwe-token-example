package io.github.chrisruffalo.jwe.model;

import javax.persistence.Entity;
import java.util.Optional;

@Entity
public class Subject extends KeyPairEntity {

    public static Optional<Subject> findByName(final String name) {
        return find("name", name).firstResultOptional();
    }

}
