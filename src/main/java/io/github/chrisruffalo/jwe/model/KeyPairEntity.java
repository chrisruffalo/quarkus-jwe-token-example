package io.github.chrisruffalo.jwe.model;

import io.quarkus.hibernate.orm.panache.PanacheEntity;

import javax.persistence.FetchType;
import javax.persistence.MappedSuperclass;
import javax.persistence.OneToMany;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Base class for entities that have keys attached to them.
 */
@MappedSuperclass
public abstract class KeyPairEntity extends PanacheEntity {

    public String name;

    /**
     * The pairs that are associated with this entity
     */
    @OneToMany(fetch = FetchType.LAZY)
    public List<StoredKeyPair> pairs = new ArrayList<>();

    public Optional<StoredKeyPair> getFirstActiveKeyPair() {
        return pairs.stream().filter((pair) -> pair.active).findFirst();
    }

}
