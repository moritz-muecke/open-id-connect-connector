package org.mule.modules.openidconnect.client.relyingparty;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;

import java.net.URI;

/**
 * Factory to build TokenRequest objects of the Nimbus OIDC OAuth2 SDK.
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class TokenRequestFactory {
    public TokenRequest getTokenRequest(
            URI endpoint,
            ClientAuthentication clientAuthentication,
            AuthorizationGrant authCodeGrant) {
        return new TokenRequest(endpoint, clientAuthentication, authCodeGrant);
    }
}
