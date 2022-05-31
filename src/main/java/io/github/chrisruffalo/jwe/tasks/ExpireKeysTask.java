package io.github.chrisruffalo.jwe.tasks;

import io.github.chrisruffalo.jwe.model.StoredKeyPair;
import io.quarkus.scheduler.Scheduled;
import org.jboss.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.transaction.Transactional;
import java.util.List;

@ApplicationScoped
public class ExpireKeysTask {

    @Inject
    Logger logger;

    @Transactional
    @Scheduled(every = "30s", identity = "expire-keys") // this is just housekeeping, point of use should always check isActive()
    public void expireKeys() {
        final List<StoredKeyPair> expiredPairs = StoredKeyPair.getExpiredButActiveKeyPairs();
        int expired = 0;
        for(final StoredKeyPair skp : expiredPairs) {
            logger.debugf("Expired kid:%s", skp);
            skp.active = false;
            expired++;
        }
        if (expired > 0) {
            logger.infof("Deactivated %d active but expired stored keys", expired);
        }
    }

}
