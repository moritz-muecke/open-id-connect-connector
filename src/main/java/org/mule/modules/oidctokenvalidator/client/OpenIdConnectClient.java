package org.mule.modules.oidctokenvalidator.client;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import org.mule.api.store.ObjectStoreException;
import org.mule.modules.oidctokenvalidator.client.relyingparty.RelyingPartyHandler;
import org.mule.modules.oidctokenvalidator.client.tokenvalidation.TokenValidator;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.HTTPConnectException;
import org.mule.modules.oidctokenvalidator.exception.MetaDataInitializationException;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class OpenIdConnectClient {

    private TokenValidator tokenValidator;
    private SingleSignOnConfig ssoConfig;

    private static final Logger logger = LoggerFactory.getLogger(OpenIdConnectClient.class);

    public OpenIdConnectClient(SingleSignOnConfig ssoConfig, TokenValidator tokenValidator)
            throws MetaDataInitializationException {
        this.ssoConfig = ssoConfig;
        this.tokenValidator = tokenValidator;
    }

    public Map<String, Object> ssoTokenValidation(String authHeader)
            throws TokenValidationException, HTTPConnectException {
        return tokenValidator.introspectionTokenValidation(authHeader, ssoConfig);
    }

    public Map<String, Object> localTokenValidation(String authHeader) throws TokenValidationException {
        JWTClaimsSet jwtClaimSet = tokenValidator.localTokenValidation(authHeader, ssoConfig);
        return jwtClaimSet.toJSONObject();
    }

    public void actAsRelyingParty(RelyingPartyHandler relyingPartyHandler) throws
            ObjectStoreException, ParseException, java.text.ParseException {
        if (relyingPartyHandler.hasTokenCookieAndIsStored()) {
            logger.debug("Token cookie found in request and store. Handling resource request");
            relyingPartyHandler.handleResourceRequest();
        } else if (relyingPartyHandler.hasRedirectCookieAndIsStored()) {
            logger.debug("Redirect cookie found in request and store. Handling token request");
            relyingPartyHandler.handleTokenRequest();
        } else {
            logger.debug("No matching cookies found in request and store. Handling redirect");
            relyingPartyHandler.handleRedirect();
        }
    }
}