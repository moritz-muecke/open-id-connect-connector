package org.mule.modules.oidctokenvalidator.client;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.apache.commons.httpclient.Cookie;
import org.mule.api.MuleMessage;
import org.mule.api.store.ObjectStoreException;
import org.mule.module.http.api.HttpConstants.HttpStatus;
import org.mule.module.http.api.HttpConstants.ResponseProperties;
import org.mule.module.http.api.HttpHeaders;
import org.mule.modules.oidctokenvalidator.client.oidc.RelyingPartyHandler;
import org.mule.modules.oidctokenvalidator.client.oidc.TokenRequester;
import org.mule.modules.oidctokenvalidator.client.oidc.TokenStorage;
import org.mule.modules.oidctokenvalidator.client.oidc.TokenValidator;
import org.mule.modules.oidctokenvalidator.config.ConnectorConfig;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.HTTPConnectException;
import org.mule.modules.oidctokenvalidator.exception.MetaDataInitializationException;
import org.mule.modules.oidctokenvalidator.exception.RequestTokenFromSsoException;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

public class OpenIdConnectClient {

    private TokenValidator tokenValidator;
    private SingleSignOnConfig ssoConfig;
    private ConnectorConfig config;

    public OpenIdConnectClient(
            ConnectorConfig connConfig,
            SingleSignOnConfig ssoCfg,
            TokenValidator validator) throws MetaDataInitializationException {
        ssoConfig = ssoCfg;
        config = connConfig;
        try {
            ssoConfig.buildProviderMetadata();
        } catch (Exception e) {
            throw new MetaDataInitializationException("Error during MetaData initialization from identity provider: " + e.getMessage());
        }
        tokenValidator = validator;
    }

    public Map<String, Object> ssoTokenValidation(String authHeader)
            throws TokenValidationException, HTTPConnectException {
        try {
            ssoConfig.setIntrospectionUri(new URI(ssoConfig.getSsoUri() + config.getIntrospectionEndpoint()));
        } catch (URISyntaxException e) {
            throw new TokenValidationException("Invalid introspection URL path");
        }
        ssoConfig.setClientSecretBasic(new ClientSecretBasic(new ClientID(config.getClientId()), new Secret(config.getClientSecret())));
        return tokenValidator.introspectionTokenValidation(authHeader);
    }

    public Map<String, Object> localTokenValidation(String authHeader) throws TokenValidationException {
        JWTClaimsSet jwtClaimSet = tokenValidator.localTokenValidation(authHeader);
        return jwtClaimSet.toJSONObject();
    }

    public void actAsRelyingParty(RelyingPartyHandler relyingPartyHandler) throws ObjectStoreException, ParseException, java.text.ParseException {
        if (relyingPartyHandler.hasTokenCookieAndIsStored()) {
            relyingPartyHandler.handleRequest();
        } else if (relyingPartyHandler.hasRedirectCookieAndIsStored()) {
            relyingPartyHandler.handleTokenRequest();
        } else relyingPartyHandler.handleRedirect();
    }

    public SingleSignOnConfig getSsoConfig() {
        return ssoConfig;
    }

}