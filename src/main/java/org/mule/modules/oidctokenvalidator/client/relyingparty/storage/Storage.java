package org.mule.modules.oidctokenvalidator.client.relyingparty.storage;

import org.mule.api.store.ObjectStore;
import org.mule.api.store.ObjectStoreException;

import java.io.Serializable;

public class Storage<T extends Serializable>{

    private ObjectStore<T> store;

    public Storage(ObjectStore<T> store) {
        this.store = store;
    }

    public void storeData(String entryId, T storeData) throws ObjectStoreException {
        if (store.contains(entryId)) {
            store.remove(entryId);
        }
        store.store(entryId, storeData);
    }

    public T getData(String entryId) throws ObjectStoreException {
        if (store.contains(entryId)){
            return store.retrieve(entryId);
        } else return null;
    }

    public boolean containsData(String entryId) throws ObjectStoreException {
        return entryId != null && store.contains(entryId);
    }

    public void removeData(String entryId) throws ObjectStoreException {
        if (store.contains(entryId)){
            store.remove(entryId);
        }
    }
}
