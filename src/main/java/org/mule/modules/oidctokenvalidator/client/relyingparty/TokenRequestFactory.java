package org.mule.modules.oidctokenvalidator.client.relyingparty;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import java.net.URI;

/**
 * Created by moritz.moeller on 07.03.2016.
 */
public class TokenRequestFactory {
    public TokenRequest getTokenRequest(
            URI endpoint,
            ClientAuthentication clientAuthentication,
            AuthorizationGrant authCodeGrant) {
        return new TokenRequest(endpoint, clientAuthentication, authCodeGrant);
    }
}
