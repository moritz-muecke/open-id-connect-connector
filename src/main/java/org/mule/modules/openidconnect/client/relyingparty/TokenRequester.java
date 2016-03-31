package org.mule.modules.openidconnect.client.relyingparty;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.mule.modules.openidconnect.client.NimbusParserUtil;
import org.mule.modules.openidconnect.client.relyingparty.storage.TokenData;
import org.mule.modules.openidconnect.config.SingleSignOnConfig;
import org.mule.modules.openidconnect.exception.RequestTokenFromSsoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;

/**
 * This class requests token sets from an OpenID provider. Initial token sets as well as refreshed token sets.
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class TokenRequester {

    private TokenRequestFactory tokenRequestFactory;
    private NimbusParserUtil parser;

    private static final Logger logger = LoggerFactory.getLogger(TokenRequester.class);

    public TokenRequester(){
        this.tokenRequestFactory = new TokenRequestFactory();
        this.parser = new NimbusParserUtil();
    }

    /**
     * Builds an valid AuthenticationRequest object to redirect the user to the OpenID provider for authentication.
     * Creates the state and nonce values specified by OpenID Connect by using the Nimbus OIDC OAuth2 SDK
     *
     * @param ssoConfig Config object with all necessary identity provider information
     * @return AuthenticationRequest object
     */
    public AuthenticationRequest buildAuthenticationRequest(SingleSignOnConfig ssoConfig) {
        State state = new State();
        Nonce nonce = new Nonce();
        Scope scope = Scope.parse("openid");
        ClientID clientId = ssoConfig.getClientSecretBasic().getClientID();

        return new AuthenticationRequest(
                ssoConfig.getProviderMetadata().getAuthorizationEndpointURI(),
                new ResponseType(ResponseType.Value.CODE),
                scope, clientId, ssoConfig.getRedirectUri(), state, nonce);
    }

    /**
     * Takes a given Authorization code to request a token set from the OpenID provider
     *
     * @param authCode Authorization code to request the token set
     * @param ssoConfig Config object with all necessary identity provider information
     * @return The token set
     * @throws RequestTokenFromSsoException if connection fails or request is invalid
     */
    public TokenData requestTokensFromSso(String authCode, SingleSignOnConfig ssoConfig) throws
            RequestTokenFromSsoException {
        try {
            AuthorizationCodeGrant authCodeGrant = new AuthorizationCodeGrant(
                    new AuthorizationCode(authCode), ssoConfig.getRedirectUri()
            );
            TokenRequest tokenReq = tokenRequestFactory.getTokenRequest(
                    ssoConfig.getProviderMetadata().getTokenEndpointURI(),
                    ssoConfig.getClientSecretBasic(),
                    authCodeGrant
            );
            logger.debug("Sending token HTTP request to identity provider");
            HTTPResponse tokenHTTPResp = tokenReq.toHTTPRequest().send();
            TokenResponse tokenResponse = parser.parseTokenResponse(tokenHTTPResp);
            if (tokenResponse instanceof TokenErrorResponse) {
                logger.debug("Received an error response from token request");
                ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
                throw new RequestTokenFromSsoException(error.getDescription());
            }
            OIDCTokenResponse oidcTokenResponse = (OIDCTokenResponse) tokenResponse;
            OIDCTokens tokens = oidcTokenResponse.getOIDCTokens();
            return new TokenData(tokens);
        } catch (Exception e) {
            throw new RequestTokenFromSsoException(e.getMessage());
        }
    }

    /**
     * Request a new token set by sending a request with a given refresh token to the OpenID provider
     *
     * @param tokenData Current token data
     * @param ssoConfig Config object with all necessary identity provider information
     * @return Refreshed token set
     * @throws RequestTokenFromSsoException if request is invalid
     * @throws IOException if connection fails
     * @throws ParseException if tokens can't be parsed
     */
    public TokenData refreshTokenSet(TokenData tokenData, SingleSignOnConfig ssoConfig) throws
            RequestTokenFromSsoException, IOException, ParseException {
        RefreshToken refreshToken = tokenData.getRefreshToken();
        AuthorizationGrant refreshTokenGrant = new RefreshTokenGrant(refreshToken);

        ClientAuthentication clientAuth = ssoConfig.getClientSecretBasic();

        URI tokenEndpoint = ssoConfig.getProviderMetadata().getTokenEndpointURI();

        TokenRequest request = tokenRequestFactory.getTokenRequest(tokenEndpoint, clientAuth, refreshTokenGrant);

        logger.debug("Sending token refresh HTTP request to identity provider");
        TokenResponse response = parser.parseTokenResponse(request.toHTTPRequest().send());
        if(response instanceof TokenErrorResponse) {
            logger.debug("Received an error response from token refresh request");
            throw new RequestTokenFromSsoException("Refresh tokens from SSO failed");
        }
        OIDCTokenResponse oidcTokenResponse = (OIDCTokenResponse) response;

        OIDCTokens refreshedTokens = oidcTokenResponse.getOIDCTokens();
        return new TokenData(refreshedTokens, tokenData.getCookieId());
    }

    public void setTokenRequestFactory(TokenRequestFactory tokenRequestFactory) {
        this.tokenRequestFactory = tokenRequestFactory;
    }

    public void setParser(NimbusParserUtil parser) {
        this.parser = parser;
    }
}
