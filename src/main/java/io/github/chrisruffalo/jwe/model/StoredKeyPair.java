package io.github.chrisruffalo.jwe.model;


import io.quarkus.hibernate.orm.panache.PanacheEntity;

import javax.persistence.Entity;
import javax.persistence.Lob;
import java.util.*;

/**
 * Stores a keypair in a way that it can be used by the application without
 * much transforming (usually just loading the binary encoding).
 */
@Entity
public class StoredKeyPair extends PanacheEntity {

    /**
     * The key id used for later key resolution
     */
    public String kid;

    /**
     * If the key is active or not. Only an _active_ key should
     * be used for encryption. An inactive key is probably in the
     * process of being rotated out.
     */
    public boolean active;

    /**
     * This is a jumping-off point for supporting multiple key types, right now
     * only RSA is used but this will be used to determine how to construct
     * the key from this one.
     */
    public KeyType keyType;

    /**
     * When a key expires it should be deactivated by a periodic task
     * which will automatically revoke all keys.
     */
    public Date expires;

    /**
     * Raw JWK as json that is created when the key is
     * created and persisted to the DB
     */
    @Lob
    public String jwk;

    /**
     * Implementation-specific private key serialized to bytes.
     */
    @Lob
    public byte[] privateKey;

    /**
     * Implementation-specific public key serialized to bytes.
     */
    @Lob
    public byte[] publicKey;

    public boolean isActive() {
        // check active status
        if (!active) {
            return false;
        }
        // check expiration
        if (expires != null) {
            final Calendar expireCalendar = Calendar.getInstance();
            expireCalendar.setTime(expires);
            return Calendar.getInstance().before(expireCalendar);
        }
        return true;
    }

    public static Optional<StoredKeyPair> getKeyPairByKid(final String kid) {
        return find("kid", kid).firstResultOptional();
    }

    public static List<StoredKeyPair> getExpiredButActiveKeyPairs() {
        final Map<String, Object> params = new HashMap<>();
        params.put("now", new Date());
        return find("expires < :now and active = true", params).list();
    }
}
