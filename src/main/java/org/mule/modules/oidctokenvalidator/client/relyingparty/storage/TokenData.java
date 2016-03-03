package org.mule.modules.oidctokenvalidator.client.relyingparty.storage;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import java.io.Serializable;
import java.util.UUID;

/**
 * Created by moritz.moeller on 03.03.2016.
 */
public class TokenData implements Serializable {
    private String cookieId;
    private JWT idToken;
    private AccessToken accessToken;
    private RefreshToken refreshToken;

    public TokenData(OIDCTokens tokens) {
        this.idToken = tokens.getIDToken();
        this.accessToken = tokens.getAccessToken();
        this.refreshToken = tokens.getRefreshToken();
        this.cookieId = UUID.randomUUID().toString();
    }

    public TokenData(OIDCTokens tokens, String cookieId) {
        this(tokens);
        this.cookieId = cookieId;
    }

    public JWT getIdToken() {
        return idToken;
    }

    public void setIdToken(JWT idToken) {
        this.idToken = idToken;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getCookieId() {
        return cookieId;
    }
}
