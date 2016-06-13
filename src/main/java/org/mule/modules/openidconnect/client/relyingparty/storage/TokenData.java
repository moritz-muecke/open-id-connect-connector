/**
 * Copyright 2016 Moritz Möller, AOE GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
