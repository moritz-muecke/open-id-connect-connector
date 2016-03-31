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
 * Created by moritz.moeller on 01.03.2016.
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

    public boolean hasTokenCookieAndIsStored() throws ObjectStoreException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        return tokenStorage.containsData(cookieExtractor(cookieHeader, TOKEN_COOKIE_NAME));
    }

    public boolean hasRedirectCookieAndIsStored() throws ObjectStoreException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        return redirectDataStorage.containsData(cookieExtractor(cookieHeader, REDIRECT_COOKIE_NAME));
    }

    public void handleResourceRequest() throws ObjectStoreException, ParseException, java.text.ParseException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String tokenStorageEntryId = cookieExtractor(cookieHeader, TOKEN_COOKIE_NAME);
        TokenData tokenData = tokenStorage.getData(tokenStorageEntryId);
        if (instantRefresh || !verifier.isActive(tokenData.getAccessToken())) {
            try {
                logger.debug("Refreshing tokens from Identity-Provider");
                tokenData = refreshTokens(tokenData);
                storeAndSetTokenCookie(tokenData);
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

    public TokenData refreshTokens(TokenData tokenData) throws
            TokenValidationException, ParseException, RequestTokenFromSsoException, IOException {
        TokenData refreshedTokenData = tokenRequester.refreshTokenSet(tokenData, ssoConfig);
        verifier.verifyRefreshedIdToken(tokenData.getIdToken(), refreshedTokenData.getIdToken());
        return refreshedTokenData;
    }

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
                storeAndSetTokenCookie(tokenData);
                logger.debug("Redirecting to origin to clear uri");
                redirectToUri(ssoConfig.getRedirectUri());
            } catch (RequestTokenFromSsoException | TokenValidationException e) {
                logger.debug("Could not request tokens from identity provider. Redirecting to Identity-Provider");
                handleRedirect();
            }
        }
    }

    public void handleRedirect() throws ObjectStoreException {
        AuthenticationRequest authRequest = tokenRequester.buildRedirectRequest(ssoConfig);
        RedirectData redirectData = new RedirectData(authRequest.getNonce(), authRequest.getState());
        storeAndSetRedirectCookie(redirectData);
        redirectToUri(authRequest.toURI());
    }

    public void storeAndSetRedirectCookie(RedirectData redirectData) throws ObjectStoreException {
        logger.debug("Storing redirect data and setting the cookie");
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String tokenStorageEntryId = cookieExtractor(cookieHeader, TOKEN_COOKIE_NAME);
        if (tokenStorageEntryId != null) tokenStorage.removeData(tokenStorageEntryId);
        redirectDataStorage.storeData(redirectData.getCookieId(), redirectData);
        Cookie cookie = new Cookie(
                ssoConfig.getRedirectUri().toString(),
                REDIRECT_COOKIE_NAME,
                redirectData.getCookieId(),
                null,
                null,
                true
        );
        muleMessage.setOutboundProperty(HttpHeaders.Names.SET_COOKIE, cookie);
    }

    public void storeAndSetTokenCookie(TokenData tokenData) throws ObjectStoreException {
        logger.debug("Storing token data and setting the cookie");
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String redirectStorageEntryId = cookieExtractor(cookieHeader, REDIRECT_COOKIE_NAME);
        if (redirectStorageEntryId != null) redirectDataStorage.removeData(redirectStorageEntryId);
        tokenStorage.storeData(tokenData.getCookieId(), tokenData);
        Cookie cookie = new Cookie(
                ssoConfig.getRedirectUri().toString(),
                TOKEN_COOKIE_NAME,
                tokenData.getCookieId(),
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
