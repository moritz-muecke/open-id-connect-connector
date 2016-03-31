package org.mule.modules.openidconnect.client;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import org.mule.api.store.ObjectStoreException;
import org.mule.modules.openidconnect.client.relyingparty.RelyingPartyHandler;
import org.mule.modules.openidconnect.client.tokenvalidation.TokenValidator;
import org.mule.modules.openidconnect.config.SingleSignOnConfig;
import org.mule.modules.openidconnect.exception.HTTPConnectException;
import org.mule.modules.openidconnect.exception.MetaDataInitializationException;
import org.mule.modules.openidconnect.exception.TokenValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * The OpenIDConnectClient is used to access the different features of this connector. It provides the entry points
 * for local and online token validation as well as the function to act as relying party
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class OpenIdConnectClient {

    private TokenValidator tokenValidator;
    private SingleSignOnConfig ssoConfig;

    private static final Logger logger = LoggerFactory.getLogger(OpenIdConnectClient.class);

    public OpenIdConnectClient(SingleSignOnConfig ssoConfig, TokenValidator tokenValidator)
            throws MetaDataInitializationException {
        this.ssoConfig = ssoConfig;
        this.tokenValidator = tokenValidator;
    }

    /**
     * Calls the TokenValidator for identity provider based token validation
     *
     * @param authHeader Authorization header string from HTTP Request
     * @return A map representing the claims of the submitted token
     * @throws TokenValidationException if the token is invalid
     * @throws HTTPConnectException if the connector can't connect to the identity provider
     */
    public Map<String, Object> ssoTokenValidation(String authHeader)
            throws TokenValidationException, HTTPConnectException {
        return tokenValidator.introspectionTokenValidation(authHeader, ssoConfig);
    }

    /**
     * Calls the TokenValidator for connector based token validation
     *
     * @param authHeader Authorization header string from HTTP Request
     * @return A map representing the claims of the submitted token
     * @throws TokenValidationException if the token is invalid
     */
    public Map<String, Object> localTokenValidation(String authHeader) throws TokenValidationException {
        JWTClaimsSet jwtClaimSet = tokenValidator.localTokenValidation(authHeader, ssoConfig);
        return jwtClaimSet.toJSONObject();
    }

    /**
     * Calls the relying party handler to act as an OpenID Connect client
     *
     * @param relyingPartyHandler The handler which contains the logic to act as a relying party
     * @throws ObjectStoreException if the cookies cant be stored or retrieved from memory
     * @throws ParseException
     * @throws java.text.ParseException
     */
    public void actAsRelyingParty(RelyingPartyHandler relyingPartyHandler) throws
            ObjectStoreException, ParseException, java.text.ParseException {
        System.out.println(relyingPartyHandler.hasCookieAndExistsInStore(RelyingPartyHandler.TOKEN_COOKIE_NAME));
        System.out.println(relyingPartyHandler.hasCookieAndExistsInStore(RelyingPartyHandler.REDIRECT_COOKIE_NAME));

        if (relyingPartyHandler.hasCookieAndExistsInStore(RelyingPartyHandler.TOKEN_COOKIE_NAME)) {
            logger.debug("Token cookie found in request and store. Handling resource request");
            relyingPartyHandler.handleResourceRequest();
        } else if (relyingPartyHandler.hasCookieAndExistsInStore(RelyingPartyHandler.REDIRECT_COOKIE_NAME)) {
            logger.debug("Redirect cookie found in request and store. Handling token request");
            relyingPartyHandler.handleTokenRequest();
        } else {
            logger.debug("No matching cookies found in request and store. Handling redirect to identity provider");
            relyingPartyHandler.handleRedirect();
        }
    }
}