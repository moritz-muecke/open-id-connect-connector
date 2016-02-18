package org.mule.modules.oidctokenvalidator.client.oidc;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.RequestTokenFromSsoException;

import java.net.URI;

/**
 * Created by moritz.moeller on 17.02.2016.
 */
public interface TokenRequester {
    URI buildRedirectUri();
    OIDCTokens requestTokensFromSso(String authCode) throws RequestTokenFromSsoException;
    OIDCTokens requestNewRefreshToken(OIDCTokens tokens);
}
