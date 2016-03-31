package org.mule.modules.openidconnect.client.relyingparty.storage;

import java.io.Serializable;
import java.util.UUID;

/**
 * Created by moritz.moeller on 31.03.2016.
 */
public abstract class StorageData implements Serializable{
    String cookieId;

    StorageData() {
        this.cookieId = UUID.randomUUID().toString();
    }

    public String getCookieId() {
        return cookieId;
    }
}
