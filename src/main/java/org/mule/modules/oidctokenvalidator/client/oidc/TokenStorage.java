package org.mule.modules.oidctokenvalidator.client.oidc;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.mule.api.store.ListableObjectStore;
import org.mule.api.store.ObjectStore;
import org.mule.api.store.ObjectStoreException;

/**
 * Created by moritz.moeller on 17.02.2016.
 */
public interface TokenStorage {
    String getTokens(String storageEntryId) throws ObjectStoreException;
    void storeTokens(String storageEntryId, String tokens) throws ObjectStoreException;
}
