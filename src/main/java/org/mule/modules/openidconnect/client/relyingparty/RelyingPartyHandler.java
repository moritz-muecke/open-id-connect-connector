package org.mule.modules.openidconnect.client.relyingparty;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.commons.httpclient.Cookie;
import org.mule.api.MuleMessage;
import org.mule.api.store.ObjectStoreException;
import org.mule.module.http.api.HttpConstants;
import org.mule.module.http.api.HttpHeaders;
import org.mule.modules.openidconnect.client.relyingparty.storage.RedirectData;
import org.mule.modules.openidconnect.client.relyingparty.storage.Storage;
import org.mule.modules.openidconnect.client.relyingparty.storage.StorageData;
import org.mule.modules.openidconnect.client.relyingparty.storage.TokenData;
import org.mule.modules.openidconnect.client.tokenvalidation.TokenVerifier;
import org.mule.modules.openidconnect.config.SingleSignOnConfig;
import org.mule.modules.openidconnect.exception.RequestTokenFromSsoException;
import org.mule.modules.openidconnect.exception.TokenValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Map;

/**
 * This class provides all the logic needed by the connector to act as a OpenID Connect relying party. Handles the
 * redirects as well as the refreshing, requesting and storing of the token data. Sets Cookies at consumer side.
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class RelyingPartyHandler {

    public static final String TOKEN_COOKIE_NAME = "ESB-OIDC-SID";
    public static final String REDIRECT_COOKIE_NAME = "ESB-OIDC-RID";
    private TokenRequester tokenRequester;
    private Storage<TokenData> tokenStorage;
    private Storage<RedirectData> redirectDataStorage;
    private MuleMessage muleMessage;
    private SingleSignOnConfig ssoConfig;
    private TokenVerifier verifier;
    private boolean instantRefresh;

    private static final Logger logger = LoggerFactory.getLogger(RelyingPartyHandler.class);


    public RelyingPartyHandler(
            MuleMessage muleMessage,
            TokenRequester tokenRequester,
            Storage<TokenData> tokenStorage,
            Storage<RedirectData> redirectDataStorage,
            SingleSignOnConfig ssoConfig,
            TokenVerifier verifier,
            boolean instantRefresh) {
        this.tokenRequester = tokenRequester;
        this.tokenStorage = tokenStorage;
        this.redirectDataStorage = redirectDataStorage;
        this.muleMessage = muleMessage;
        this.ssoConfig = ssoConfig;
        this.verifier = verifier;
        this.instantRefresh = instantRefresh;
    }

    /**
     * Checks if a cookie with given name is in the current request and if this cookie is stored in the Mule ObjectStore
     * @return True if it is stored, false if not
     * @throws ObjectStoreException if there is a problem reading data from Mule ObjectStore
     */
    public boolean hasCookieAndExistsInStore(String cookieName) throws ObjectStoreException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        System.out.println(cookieExtractor(cookieHeader, cookieName));
        if (cookieName.equals(TOKEN_COOKIE_NAME)){
            return tokenStorage.containsData(cookieExtractor(cookieHeader, cookieName));
        } else {
            return redirectDataStorage.containsData(cookieExtractor(cookieHeader, cookieName));
        }
    }

    /**
     * Handles the resource request if tokens are available and active. If not active the method try's to refresh
     * them
     *
     * @throws ObjectStoreException If refreshed tokens can't be stored
     * @throws ParseException If tokens can't be parsed
     * @throws java.text.ParseException
     */
    public void handleResourceRequest() throws ObjectStoreException, ParseException, java.text.ParseException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String tokenStorageEntryId = cookieExtractor(cookieHeader, TOKEN_COOKIE_NAME);
        TokenData tokenData = tokenStorage.getData(tokenStorageEntryId);
        if (instantRefresh || !verifier.isActive(tokenData.getAccessToken())) {
            try {
                logger.debug("Refreshing tokens from Identity-Provider");
                tokenData = refreshTokens(tokenData);
                storeAndSetCookie(tokenData, tokenStorage, TOKEN_COOKIE_NAME);
            } catch (IOException | TokenValidationException | RequestTokenFromSsoException e) {
                logger.debug("Could not refresh tokens from identity provider. Redirecting to Identity-Provider");
                handleRedirect();
                return;
            }
        }
        muleMessage.setOutboundProperty(
                HttpHeaders.Names.AUTHORIZATION, "Bearer " + tokenData.getAccessToken().getValue()
        );
    }

    /**
     * Calls the TokenVerifier to refresh a given token set
     *
     * @param tokenData Token set which has to be refreshed
     * @return Refreshed token set
     * @throws TokenValidationException If validation of the refreshed tokens fails
     * @throws ParseException If parsing of the refreshed tokens fails
     * @throws RequestTokenFromSsoException If token refreshing via the OpenID Provider fails
     * @throws IOException If connecting to the OpenID Provider fails
     */
    public TokenData refreshTokens(TokenData tokenData) throws
            TokenValidationException, ParseException, RequestTokenFromSsoException, IOException {
        TokenData refreshedTokenData = tokenRequester.refreshTokenSet(tokenData, ssoConfig);
        verifier.verifyRefreshedIdToken(tokenData.getIdToken(), refreshedTokenData.getIdToken());
        return refreshedTokenData;
    }

    /**
     * Handles requests of consumers which were redirected back to the connector by the OpenID Provider with an
     * authorization code. The Code is included in the query parameters of the current request. Calls the TokenVerifier
     * to request the tokens with the authorization code.
     *
     * @throws ObjectStoreException If the requested tokens can't be stored in Mule ObjectStore
     */
    public void handleTokenRequest() throws ObjectStoreException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String redirectEntryId = cookieExtractor(cookieHeader, REDIRECT_COOKIE_NAME);
        RedirectData redirectData = redirectDataStorage.getData(redirectEntryId);
        Map<String, String> queryParams = muleMessage.getInboundProperty("http.query.params");
        String queryState = queryParams.get("state");
        String authCode = queryParams.get("code");
        if (!redirectData.getState().getValue().equals(queryState) || authCode == null) {
            logger.debug("State mismatch or missing auth code. Redirecting to Identity-Provider");
            handleRedirect();
        } else {
            try {
                TokenData tokenData = tokenRequester.requestTokensFromSso(authCode, ssoConfig);
                verifier.verifyIdToken(tokenData.getIdToken(), ssoConfig, redirectData.getNonce());
                storeAndSetCookie(tokenData, tokenStorage, TOKEN_COOKIE_NAME);
                logger.debug("Redirecting to origin to clear uri");
                redirectToUri(ssoConfig.getRedirectUri());
            } catch (RequestTokenFromSsoException | TokenValidationException e) {
                logger.debug("Could not request tokens from identity provider. Redirecting to Identity-Provider");
                handleRedirect();
            }
        }
    }

    /**
     * If neither a redirect cookie nor a token cookie is available in the current request, the consumer is
     * redirected to the identity provider. Generates and stores redirect data
     *
     * @throws ObjectStoreException if redirect data can't be stored in Mule ObjectStore
     */
    public void handleRedirect() throws ObjectStoreException {
        AuthenticationRequest authRequest = tokenRequester.buildAuthenticationRequest(ssoConfig);
        RedirectData redirectData = new RedirectData(authRequest.getNonce(), authRequest.getState());
        storeAndSetCookie(redirectData, redirectDataStorage, REDIRECT_COOKIE_NAME);
        redirectToUri(authRequest.toURI());
    }

    public void storeAndSetCookie(StorageData storageData, Storage storage, String cookieName) throws
            ObjectStoreException {
        logger.debug("Storing data and setting the cookie");
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String storageId = cookieExtractor(cookieHeader, cookieName);
        if (storageId != null) storage.removeData(storageId);
        storage.storeData(storageData.getCookieId(), storageData);
        Cookie cookie = new Cookie(
                ssoConfig.getRedirectUri().toString(),
                cookieName,
                storageData.getCookieId(),
                null,
                null,
                true
        );
        muleMessage.setOutboundProperty(HttpHeaders.Names.SET_COOKIE, cookie);
    }

    public void redirectToUri(URI redirectUri) {
        muleMessage.setOutboundProperty(
                HttpConstants.ResponseProperties.HTTP_STATUS_PROPERTY,
                HttpConstants.HttpStatus.MOVED_TEMPORARILY.getStatusCode()
        );
        muleMessage.setOutboundProperty(
                HttpConstants.ResponseProperties.HTTP_REASON_PROPERTY,
                HttpConstants.HttpStatus.MOVED_TEMPORARILY.getReasonPhrase()
        );
        muleMessage.setOutboundProperty(HttpHeaders.Names.LOCATION, redirectUri);
    }

    public String cookieExtractor(String header, String cookieName) {
        if (header != null){
            return Arrays.stream(header.split("; "))
                    .filter(c -> c.split("=")[0].equals(cookieName))
                    .map(c -> c.split("=")[1])
                    .findFirst().orElse(null);
        } else return null;
    }

    public void setInstantRefresh(boolean instantRefresh) {
        this.instantRefresh = instantRefresh;
    }
}
