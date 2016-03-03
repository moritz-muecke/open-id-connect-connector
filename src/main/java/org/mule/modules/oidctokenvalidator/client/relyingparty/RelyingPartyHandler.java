package org.mule.modules.oidctokenvalidator.client.relyingparty;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.commons.httpclient.Cookie;
import org.mule.api.MuleMessage;
import org.mule.api.store.ObjectStoreException;
import org.mule.module.http.api.HttpConstants;
import org.mule.module.http.api.HttpHeaders;
import org.mule.modules.oidctokenvalidator.client.relyingparty.storage.RedirectData;
import org.mule.modules.oidctokenvalidator.client.relyingparty.storage.Storage;
import org.mule.modules.oidctokenvalidator.client.relyingparty.storage.TokenData;
import org.mule.modules.oidctokenvalidator.client.tokenvalidation.TokenVerifier;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.RequestTokenFromSsoException;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;

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
    private boolean instantRefresh;

    public RelyingPartyHandler(
            MuleMessage muleMessage,
            TokenRequester tokenRequester,
            Storage<TokenData> tokenStorage,
            Storage<RedirectData> redirectDataStorage,
            SingleSignOnConfig ssoConfig,
            boolean instantRefresh) {
        this.tokenRequester = tokenRequester;
        this.tokenStorage = tokenStorage;
        this.redirectDataStorage = redirectDataStorage;
        this.muleMessage = muleMessage;
        this.ssoConfig = ssoConfig;
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

    public void handleRequest() throws ObjectStoreException, ParseException, java.text.ParseException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String tokenStorageEntryId = cookieExtractor(cookieHeader, TOKEN_COOKIE_NAME);
        String redirectStorageEntryId = cookieExtractor(cookieHeader, REDIRECT_COOKIE_NAME);
        TokenData tokenData = tokenStorage.getData(tokenStorageEntryId);
        if (instantRefresh) {
            tokenData = refreshTokens(tokenData, tokenStorageEntryId, redirectStorageEntryId);
        } else if(!TokenVerifier.isActive(tokenData.getAccessToken())) {
            tokenData = refreshTokens(tokenData, tokenStorageEntryId, redirectStorageEntryId);
        }
        muleMessage.setOutboundProperty(HttpHeaders.Names.AUTHORIZATION, "Bearer " + tokenData.getAccessToken().getValue());
    }

    public void handleTokenRequest() throws ObjectStoreException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String redirectEntryId = cookieExtractor(cookieHeader, REDIRECT_COOKIE_NAME);
        RedirectData redirectData = redirectDataStorage.getData(redirectEntryId);
        Map<String, String> queryParams = muleMessage.getInboundProperty("http.query.params");
        String queryState = queryParams.get("state");
        String authCode = queryParams.get("code");
        if (!redirectData.getState().getValue().equals(queryState) || authCode == null) {
            handleRedirect();
        }
        try {
            TokenData tokenData = tokenRequester.requestTokensFromSso(authCode, ssoConfig);
            TokenVerifier.verifyIdToken(tokenData.getIdToken(), ssoConfig, redirectData.getNonce());
            storeAndSetTokenCookie(tokenData);
            redirectDataStorage.removeData(redirectEntryId);
            muleMessage.setOutboundProperty(HttpHeaders.Names.AUTHORIZATION, "Bearer " + tokenData.getAccessToken().getValue());
        } catch (RequestTokenFromSsoException | TokenValidationException e) {
            redirectDataStorage.removeData(redirectEntryId);
            handleRedirect();
        }
    }

    public void handleRedirect() throws ObjectStoreException {
        AuthenticationRequest authRequest = tokenRequester.buildRedirectRequest(ssoConfig);
        RedirectData redirectData = new RedirectData(authRequest.getNonce(), authRequest.getState());
        storeAndSetRedirectCookie(redirectData);
        setRedirectToSso(authRequest.toURI());
    }

    private TokenData refreshTokens(TokenData tokenData, String tokenStorageEntryId, String redirectStorageEntryId) throws ObjectStoreException, ParseException {
        TokenData refreshedTokenData = null;
        try {
            refreshedTokenData = tokenRequester.refreshTokenSet(tokenData, ssoConfig);
            TokenVerifier.verifyRefreshedIdToken(tokenData.getIdToken(), refreshedTokenData.getIdToken());
            storeAndSetTokenCookie(refreshedTokenData);
        } catch (RequestTokenFromSsoException | IOException | TokenValidationException e) {
            tokenStorage.removeData(tokenStorageEntryId);
            redirectDataStorage.removeData(redirectStorageEntryId);
            handleRedirect();
        }
        return refreshedTokenData;
    }

    public void storeAndSetRedirectCookie(RedirectData redirectData) throws ObjectStoreException {
        redirectDataStorage.storeData(redirectData.getCookieId(), redirectData);
        Cookie cookie = new Cookie(ssoConfig.getRedirectUri().toString(), REDIRECT_COOKIE_NAME, redirectData.getCookieId());
        muleMessage.setOutboundProperty(HttpHeaders.Names.SET_COOKIE, cookie);
    }

    public void storeAndSetTokenCookie(TokenData tokenData) throws ObjectStoreException {
        tokenStorage.storeData(tokenData.getCookieId(), tokenData);
        Cookie cookie = new Cookie(ssoConfig.getRedirectUri().toString(), TOKEN_COOKIE_NAME, tokenData.getCookieId());
        muleMessage.setOutboundProperty(HttpHeaders.Names.SET_COOKIE, cookie);
    }

    public void setRedirectToSso(URI redirectUri) {
        muleMessage.setOutboundProperty(HttpConstants.ResponseProperties.HTTP_STATUS_PROPERTY, HttpConstants.HttpStatus.MOVED_TEMPORARILY.getStatusCode());
        muleMessage.setOutboundProperty(HttpConstants.ResponseProperties.HTTP_REASON_PROPERTY, HttpConstants.HttpStatus.MOVED_TEMPORARILY.getReasonPhrase());
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
}
