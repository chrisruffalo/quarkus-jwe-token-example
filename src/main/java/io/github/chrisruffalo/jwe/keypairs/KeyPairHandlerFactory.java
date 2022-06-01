package io.github.chrisruffalo.jwe.keypairs;

import io.github.chrisruffalo.jwe.keypairs.impl.ec.EC256KeyPairHandler;
import io.github.chrisruffalo.jwe.keypairs.impl.ec.EC384KeyPairHandler;
import io.github.chrisruffalo.jwe.keypairs.impl.ec.EC521KeyPairHandler;
import io.github.chrisruffalo.jwe.keypairs.impl.rsa.RSA2048KeyPairHandler;
import io.github.chrisruffalo.jwe.keypairs.impl.rsa.RSA4096KeyPairHandler;
import io.github.chrisruffalo.jwe.model.KeyType;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.HashMap;
import java.util.Map;

/**
 * Allows runtime selection of the appropriate key handler depending on the
 * chosen key type.
 */
@ApplicationScoped
public class KeyPairHandlerFactory {

    @Inject
    EC256KeyPairHandler ec256KeyPairHandler;

    @Inject
    EC384KeyPairHandler ec384KeyPairHandler;

    @Inject
    EC521KeyPairHandler ec521KeyPairHandler;

    @Inject
    RSA2048KeyPairHandler rsa2048KeyPairHandler;

    @Inject
    RSA4096KeyPairHandler rsa4096KeyPairHandler;

    private final Map<KeyType, KeyPairHandler> handlers = new HashMap<>();

    @PostConstruct
    public void init() {
        handlers.put(KeyType.RSA, rsa2048KeyPairHandler); // 2048 is the default rsa
        handlers.put(KeyType.RSA2048, rsa2048KeyPairHandler);
        handlers.put(KeyType.RSA4096, rsa4096KeyPairHandler);
        handlers.put(KeyType.EC, ec256KeyPairHandler); //256 is the default EC handler
        handlers.put(KeyType.EC256, ec256KeyPairHandler);
        handlers.put(KeyType.EC384, ec384KeyPairHandler);
        handlers.put(KeyType.EC521, ec521KeyPairHandler);
    }

    /**
     * Given a key type return the key handler implementation for generating and parsing the keys.
     *
     * @param type of the key
     * @return a handler that matches the type. defaults to RSA2048.
     */
    public KeyPairHandler get(final KeyType type) {
        KeyPairHandler handler = handlers.get(type);
        if (handler == null) {
            handler = handlers.get(KeyType.DEFAULT);
        }
        if (handler != null) {
            return handler;
        }
        return rsa2048KeyPairHandler; // hard-coded default
    }

}
