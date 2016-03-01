package org.mule.modules.oidctokenvalidator.client.oidc;

import com.nimbusds.oauth2.sdk.TokenRequest;
import org.mule.api.store.ObjectStore;
import org.mule.api.store.ObjectStoreException;

/**
 * Created by moritz.moeller on 01.03.2016.
 */
public class RedirectDataStorage implements Storage<RedirectData> {

    private ObjectStore<RedirectData> redirectDataStore;

    public RedirectDataStorage(ObjectStore<RedirectData> redirectDataStore) {
        this.redirectDataStore = redirectDataStore;
    }

    @Override
    public void storeData(String entryId, RedirectData redirectData) throws ObjectStoreException {
        if (redirectDataStore.contains(entryId)) {
            redirectDataStore.remove(entryId);
        }
        redirectDataStore.store(entryId, redirectData);
    }

    @Override
    public RedirectData getData(String entryId) throws ObjectStoreException {
        if (redirectDataStore.contains(entryId)){
            return redirectDataStore.retrieve(entryId);
        } else return null;
    }
}
