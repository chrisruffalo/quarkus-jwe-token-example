package io.github.chrisruffalo.jwe.keypairs.impl.rsa;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class RSA2048KeyPairHandler extends RSAKeyPairHandler {

    @Override
    protected int getKeySize() {
        return 2048;
    }

}
