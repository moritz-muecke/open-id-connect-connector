package org.mule.modules.openidconnect.client.relyingparty.storage;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import java.io.Serializable;
import java.util.UUID;

/**
 * Simple POJO to represent the token data saved in the Mule ObjectStore
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class TokenData extends StorageData {
    private JWT idToken;
    private AccessToken accessToken;
    private RefreshToken refreshToken;

    public TokenData(OIDCTokens tokens) {
        this.idToken = tokens.getIDToken();
        this.accessToken = tokens.getAccessToken();
        this.refreshToken = tokens.getRefreshToken();
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

}
