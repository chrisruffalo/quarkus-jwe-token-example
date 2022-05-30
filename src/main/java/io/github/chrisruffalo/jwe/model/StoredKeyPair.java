package io.github.chrisruffalo.jwe.model;


import io.quarkus.hibernate.orm.panache.PanacheEntity;

import javax.persistence.Entity;
import javax.persistence.Lob;
import java.util.Date;
import java.util.Optional;

@Entity
public class StoredKeyPair extends PanacheEntity {

    /**
     * The key id used for later key resolution
     */
    public String kid;

    /**
     * If the key is active or not. Only an _active_ key should
     * be used for encryption. An inactive key is in the process of being
     * rotated out.
     */
    public boolean active;

    public Date expires;

    /**
     * Raw JWK as json that is created when the key is
     * created and persisted to the DB
     */
    @Lob
    public String jwk;

    @Lob
    public byte[] privateKey;

    @Lob
    public byte[] publicKey;

    public static Optional<StoredKeyPair> getKeyPairByKid(final String kid) {
        return find("kid", kid).firstResultOptional();
    }
}
