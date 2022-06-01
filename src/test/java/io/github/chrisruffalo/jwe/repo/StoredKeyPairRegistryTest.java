package io.github.chrisruffalo.jwe.repo;

import io.github.chrisruffalo.jwe.model.KeyType;
import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;

@QuarkusTest
public class StoredKeyPairRegistryTest {

    @Inject
    StoredKeyPairRegistry registry;

    @Test
    public void createRSAKey() {
        final StoredKeyPair storedKeyPair = registry.createNewKeyPair(KeyType.RSA);
        Assertions.assertNotNull(storedKeyPair);
        Assertions.assertNotNull(storedKeyPair.originalPair);
    }

    @Test
    public void createECKey() {
        final StoredKeyPair storedKeyPair = registry.createNewKeyPair(KeyType.RSA);
        Assertions.assertNotNull(storedKeyPair);
        Assertions.assertNotNull(storedKeyPair.originalPair);
    }

}
