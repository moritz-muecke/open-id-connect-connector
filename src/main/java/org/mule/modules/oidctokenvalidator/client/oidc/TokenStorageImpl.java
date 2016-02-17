package org.mule.modules.oidctokenvalidator.client.oidc;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.mule.api.store.ObjectStore;

public class TokenStorageImpl implements TokenStorage{

    private ObjectStore<String> tokenStore;

    @Override
    public OIDCTokens getTokens(String tokenStorageId) {
        return null;
    }

    @Override
    public String storeTokens(OIDCTokens tokens) {
        return null;
    }
}
