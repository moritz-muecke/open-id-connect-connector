package org.mule.modules.oidctokenvalidator.client.oidc;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;

import java.net.URI;

public class TokenRequesterImpl implements TokenRequester{

    @Override
    public URI buildRedirectUri(SingleSignOnConfig ssoConfig) {
        return null;
    }

    @Override
    public OIDCTokens requestTokensFromSso(String authCode) {
        return null;
    }

    @Override
    public OIDCTokens requestNewRefreshToken(OIDCTokens tokens) {
        return null;
    }
}
