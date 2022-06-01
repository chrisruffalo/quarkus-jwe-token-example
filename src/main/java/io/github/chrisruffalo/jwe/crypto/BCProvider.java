package io.github.chrisruffalo.jwe.crypto;

import io.quarkus.runtime.Startup;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import javax.annotation.PostConstruct;
import javax.inject.Singleton;
import java.security.Provider;
import java.security.Security;

/**
 * At startup this will inject a properly configured BCFIPS provider as the
 * default provider and make it available for injection here, as needed.
 */
@Startup
@Singleton
public class BCProvider {

    private BouncyCastleFipsProvider bouncyCastleFipsProvider;

    @PostConstruct
    public void init() {
        // this is used to insert the bouncy castle provider as the first/default provider. it is configured a little
        // differently because on some providers (openshift) the underlying entropy is not enough to fuel operations
        final BouncyCastleFipsProvider bouncyCastleFipsProvider = new BouncyCastleFipsProvider("C:HYBRID;ENABLE{All};");
        Security.insertProviderAt(bouncyCastleFipsProvider, 0);
        this.bouncyCastleFipsProvider = bouncyCastleFipsProvider;
    }

    public Provider provider() {
        return bouncyCastleFipsProvider;
    }

}
