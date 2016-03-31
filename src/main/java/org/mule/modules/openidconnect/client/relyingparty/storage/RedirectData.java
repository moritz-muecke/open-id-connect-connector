package org.mule.modules.openidconnect.client.relyingparty.storage;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;

import java.io.Serializable;
import java.util.UUID;

/**
 * Simple POJO to represent the redirect data saved in the Mule ObjectStore
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class RedirectData extends StorageData {

    private Nonce nonce;
    private State state;
    private String jsonTokens;

    public RedirectData(Nonce nonce, State state) {
        this.nonce = nonce;
        this.state = state;
    }

    public Nonce getNonce() {
        return nonce;
    }

    public State getState() {
        return state;
    }

    public String getJsonTokens() {
        return jsonTokens;
    }

    public void setJsonTokens(String jsonTokens) {
        this.jsonTokens = jsonTokens;
    }

}
