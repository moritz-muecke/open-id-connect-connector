package org.mule.modules.oidctokenvalidator.client.oidc;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.RequestTokenFromSsoException;

import java.io.IOException;
import java.net.URI;

public class TokenRequesterImpl implements TokenRequester{

    private SingleSignOnConfig ssoConfig;

    public TokenRequesterImpl(SingleSignOnConfig config) {
        ssoConfig = config;
    }

    @Override
    public URI buildRedirectUri() {
        State state = new State();
        Nonce nonce = new Nonce();
        Scope scope = Scope.parse("openid");
        ClientID clientId = ssoConfig.getClientSecretBasic().getClientID();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                ssoConfig.getProviderMetadata().getAuthorizationEndpointURI(),
                new ResponseType(ResponseType.Value.CODE),
                scope, clientId, ssoConfig.getRedirectUri(), state, nonce);

        return authenticationRequest.toURI();
    }

    @Override
    public OIDCTokens requestTokensFromSso(String authCode) throws RequestTokenFromSsoException {
        AuthorizationCodeGrant authCodeGrant = new AuthorizationCodeGrant(new AuthorizationCode(authCode), ssoConfig.getRedirectUri());
        TokenRequest tokenReq = new TokenRequest(ssoConfig.getProviderMetadata().getTokenEndpointURI(), ssoConfig.getClientSecretBasic(), authCodeGrant);

        try {
            HTTPResponse tokenHTTPResp = tokenReq.toHTTPRequest().send();
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
            if (tokenResponse instanceof TokenErrorResponse) {
                ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
                throw new RequestTokenFromSsoException(error.getDescription());
            }
            OIDCTokenResponse oidcTokenResponse = (OIDCTokenResponse) tokenResponse;
            return oidcTokenResponse.getOIDCTokens();
        } catch (IOException | ParseException e) {
            throw new RequestTokenFromSsoException(e.getMessage());
        }
    }

    @Override
    public OIDCTokens requestNewRefreshToken(OIDCTokens tokens) {
        return null;
    }
}
