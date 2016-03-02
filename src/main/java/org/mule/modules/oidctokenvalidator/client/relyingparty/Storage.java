package org.mule.modules.oidctokenvalidator.client.relyingparty;

import org.mule.api.store.ObjectStoreException;

/**
 * Created by moritz.moeller on 01.03.2016.
 */
public interface Storage<T> {
    public void storeData(String entryId, T t) throws ObjectStoreException;
    public T getData(String entryId) throws ObjectStoreException;
    public boolean containsData(String entryId) throws ObjectStoreException;
    public void removeData(String entryId) throws ObjectStoreException;
}
