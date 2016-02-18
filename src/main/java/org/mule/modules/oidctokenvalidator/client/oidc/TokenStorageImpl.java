package org.mule.modules.oidctokenvalidator.client.oidc;

import org.mule.api.store.ObjectStore;
import org.mule.api.store.ObjectStoreException;

public class TokenStorageImpl implements TokenStorage{


    private ObjectStore<String> tokenStore;

    public TokenStorageImpl(ObjectStore<String> store) {
        tokenStore = store;
    }

    @Override
    public String getTokens(String storageEntryId) throws ObjectStoreException {
        if (tokenStore.contains(storageEntryId)){
            return tokenStore.retrieve(storageEntryId);
        } else return null;
    }

    @Override
    public void storeTokens(String storageEntryId, String tokens) throws ObjectStoreException {
        tokenStore.store(storageEntryId, tokens);
    }
}
