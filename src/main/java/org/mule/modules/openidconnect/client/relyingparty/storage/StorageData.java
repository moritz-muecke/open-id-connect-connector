package org.mule.modules.openidconnect.client.relyingparty.storage;

import java.io.Serializable;
import java.util.UUID;

/**
 * Abstract class for the different data types stored in the Mule ObjectStore
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public abstract class StorageData implements Serializable {
    String cookieId;

    StorageData() {
        this.cookieId = UUID.randomUUID().toString();
    }

    public String getCookieId() {
        return cookieId;
    }
}
