package org.mule.modules.oidctokenvalidator.client.oidc;

import org.mule.api.store.ObjectStore;
import org.mule.api.store.ObjectStoreException;

public class TokenStorage {


    private ObjectStore<String> tokenStore;

    public TokenStorage(ObjectStore<String> store) {
        tokenStore = store;
    }

    public String getTokens(String storageEntryId) throws ObjectStoreException {
        if (tokenStore.contains(storageEntryId)){
            return tokenStore.retrieve(storageEntryId);
        } else return null;
    }

    public void storeTokens(String storageEntryId, String tokens) throws ObjectStoreException {
        tokenStore.store(storageEntryId, tokens);
    }
}
