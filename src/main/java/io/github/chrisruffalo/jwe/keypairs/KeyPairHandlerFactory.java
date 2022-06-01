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
    EC256KeyPairHandler ec256KeyPairHandler;

    @Inject
    EC384KeyPairHandler ec384KeyPairHandler;

    @Inject
    EC521KeyPairHandler ec521KeyPairHandler;

    @Inject
    RSAKeyPairHandler rsaKeyPairHandler;

    private final Map<KeyType, KeyPairHandler> handlers = new HashMap<>();

    @PostConstruct
    public void init() {
        handlers.put(KeyType.RSA, rsaKeyPairHandler);
        handlers.put(KeyType.EC, ec256KeyPairHandler); //256 is the default EC handler
        handlers.put(KeyType.EC256, ec256KeyPairHandler);
        handlers.put(KeyType.EC384, ec384KeyPairHandler);
        handlers.put(KeyType.EC512, ec521KeyPairHandler);
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
