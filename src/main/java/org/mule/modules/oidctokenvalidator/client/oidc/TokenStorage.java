package org.mule.modules.oidctokenvalidator.client.oidc;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

/**
 * Created by moritz.moeller on 17.02.2016.
 */
public interface TokenStorage {
    OIDCTokens getTokens(String tokenStorageId);
    String storeTokens(OIDCTokens tokens);
}
