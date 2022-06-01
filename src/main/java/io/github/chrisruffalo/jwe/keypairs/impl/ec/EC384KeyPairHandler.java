package io.github.chrisruffalo.jwe.keypairs.impl.ec;

import org.jose4j.jws.AlgorithmIdentifiers;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class EC384KeyPairHandler extends ECKeyPairHandler {

    public static final String CURVE = "secp384r1";

    @Override
    protected String getCurve() {
        return CURVE;
    }

    @Override
    protected String getSignatureAlgorithmHeaderValue() {
        return AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384;
    }

}
