package io.github.chrisruffalo.jwe.keypairs;

import org.jose4j.jws.AlgorithmIdentifiers;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class EC521KeyPairHandler extends ECKeyPairHandler {

    public static final String CURVE = "secp521r1";

    @Override
    protected String getCurve() {
        return CURVE;
    }

    @Override
    protected String getSignatureAlgorithmHeaderValue() {
        return AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512;
    }
    
}
