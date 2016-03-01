package org.mule.modules.oidctokenvalidator.client.oidc;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;

import java.io.Serializable;
import java.util.UUID;

/**
 * Created by moritz.moeller on 01.03.2016.
 */
public class RedirectData implements Serializable {

    private String cookieId;
    private Nonce nonce;
    private State state;
    private String jsonTokens;

    public RedirectData(Nonce nonce, State state) {
        this.nonce = nonce;
        this.state = state;
        this.cookieId = UUID.randomUUID().toString();
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

    public String getCookieId() {
        return cookieId;
    }

}
