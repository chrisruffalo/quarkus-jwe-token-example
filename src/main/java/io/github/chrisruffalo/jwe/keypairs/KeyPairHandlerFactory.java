package io.github.chrisruffalo.jwe.keypairs;

import io.github.chrisruffalo.jwe.model.KeyType;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.HashMap;
import java.util.Map;

@ApplicationScoped
public class KeyPairHandlerFactory {

    @Inject
    ECKeyPairHandler ecKeyPairHandler;

    @Inject
    RSAKeyPairHandler rsaKeyPairHandler;

    private final Map<KeyType, KeyPairHandler> handlers = new HashMap<>();

    @PostConstruct
    public void init() {
        handlers.put(KeyType.RSA, rsaKeyPairHandler);
        handlers.put(KeyType.EC, ecKeyPairHandler);
    }

    public KeyPairHandler get(final KeyType type) {
        KeyPairHandler handler = handlers.get(type);
        if (handler == null) {
            handler = handlers.get(KeyType.DEFAULT);
        }
        if (handler != null) {
            return handler;
        }
        return rsaKeyPairHandler; // hard-coded default
    }

}
