package org.mule.modules.oidctokenvalidator.client.oidc;

import org.mule.api.annotations.lifecycle.Stop;
import org.mule.api.store.ObjectStore;
import org.mule.api.store.ObjectStoreException;

public class TokenStorage implements Storage<String>{

    private ObjectStore<String> tokenStore;

    public TokenStorage(ObjectStore<String> store) {
        tokenStore = store;
    }

    @Override
    public void storeData(String entryId, String tokenString) throws ObjectStoreException {
        if (tokenStore.contains(entryId)) {
            tokenStore.remove(entryId);
        }
        tokenStore.store(entryId, tokenString);
    }

    @Override
    public String getData(String entryId) throws ObjectStoreException {
        if (tokenStore.contains(entryId)){
            return tokenStore.retrieve(entryId);
        } else return null;
    }
}
