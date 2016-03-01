package org.mule.modules.oidctokenvalidator.client.oidc;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.apache.commons.httpclient.Cookie;
import org.apache.cxf.common.i18n.Exception;
import org.mule.api.MuleMessage;
import org.mule.api.store.ObjectStoreException;
import org.mule.module.http.api.HttpConstants;
import org.mule.module.http.api.HttpHeaders;
import org.mule.modules.oidctokenvalidator.exception.RequestTokenFromSsoException;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

/**
 * Created by moritz.moeller on 01.03.2016.
 */
public class RelyingPartyHandler {

    public static final String TOKEN_COOKIE_NAME = "ESB-OIDC-SID";
    public static final String REDIRECT_COOKIE_NAME = "ESB-OIDC-RID";
    private TokenRequester tokenRequester;
    private Storage<String> tokenStorage;
    private Storage<RedirectData> redirectDataStorage;
    private MuleMessage muleMessage;
    private boolean instantRefresh;

    public RelyingPartyHandler(
            MuleMessage muleMessage,
            TokenRequester tokenRequester,
            Storage<String> tokenStorage,
            Storage<RedirectData> redirectDataStorage,
            boolean instantRefresh) {
        this.tokenRequester = tokenRequester;
        this.tokenStorage = tokenStorage;
        this.redirectDataStorage = redirectDataStorage;
        this.muleMessage = muleMessage;
        this.instantRefresh = instantRefresh;
    }

    public boolean hasTokenCookieAndIsStored() throws ObjectStoreException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        return tokenStorage.getData(cookieExtractor(cookieHeader, TOKEN_COOKIE_NAME)) != null;
    }

    public boolean hasRedirectCookieAndIsStored() throws ObjectStoreException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        return tokenStorage.getData(cookieExtractor(cookieHeader, REDIRECT_COOKIE_NAME)) != null;
    }

    public void setInstantRefresh(boolean instantRefresh) {
        this.instantRefresh = instantRefresh;
    }

    public void handleRequest() throws ObjectStoreException, ParseException, java.text.ParseException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String entryId = cookieExtractor(cookieHeader, TOKEN_COOKIE_NAME);
        String tokenString = tokenStorage.getData(entryId);
        JSONObject jsonObject = JSONObjectUtils.parse(tokenString);
        OIDCTokens tokens = OIDCTokenResponse.parse(jsonObject).getOIDCTokens();
        if (instantRefresh || !TokenVerifier.isActive(tokens.getAccessToken())) {
            try {
                OIDCTokens refreshedTokenSet = tokenRequester.refreshTokenSet(tokens);
                storeAndSetTokenCookie(entryId, refreshedTokenSet);
            } catch (RequestTokenFromSsoException | IOException e) {
                handleRedirect();
            }
        }
    }

    public void handleRedirect() throws ObjectStoreException {
        AuthenticationRequest authRequest = tokenRequester.buildRedirectRequest();
        RedirectData redirectData = new RedirectData(authRequest.getNonce(), authRequest.getState());
        storeAndSetRedirectCookie(redirectData);
        setRedirectToSso(authRequest.toURI());
    }

    public void handleTokenRequest() throws ObjectStoreException {
        String cookieHeader = muleMessage.getInboundProperty("cookie");
        String redirectEntryId = cookieExtractor(cookieHeader, REDIRECT_COOKIE_NAME);
        RedirectData redirectData = redirectDataStorage.getData(redirectEntryId);
        Map<String, String> queryParams = muleMessage.getInboundProperty("http.query.params");
        String queryState = queryParams.get("state");
        if (!redirectData.getState().getValue().equals(queryState)) {
            handleRedirect();
        }
        String authCode = queryParams.get("code");
        try {
            OIDCTokens tokens = tokenRequester.requestTokensFromSso(authCode);
            String tokenEntryId = UUID.randomUUID().toString();
            storeAndSetTokenCookie(tokenEntryId, tokens);
        } catch (RequestTokenFromSsoException e) {
            handleRedirect();
        }
    }

    public void storeAndSetRedirectCookie(RedirectData redirectData) throws ObjectStoreException {
        redirectDataStorage.storeData(redirectData.getCookieId(), redirectData);
        Cookie cookie = new Cookie("localhost:8080", REDIRECT_COOKIE_NAME, redirectData.getCookieId());
        muleMessage.setOutboundProperty(HttpHeaders.Names.SET_COOKIE, cookie);
    }

    public void storeAndSetTokenCookie(String entryId, OIDCTokens tokens) throws ObjectStoreException {
        tokenStorage.storeData(entryId, tokens.toJSONObject().toJSONString());
        Cookie cookie = new Cookie("localhost:8080", TOKEN_COOKIE_NAME, entryId);
        muleMessage.setOutboundProperty(HttpHeaders.Names.SET_COOKIE, cookie);
    }

    public void setRedirectToSso(URI redirecturi) {
        muleMessage.setOutboundProperty(HttpConstants.ResponseProperties.HTTP_STATUS_PROPERTY, HttpConstants.HttpStatus.MOVED_TEMPORARILY.getStatusCode());
        muleMessage.setOutboundProperty(HttpConstants.ResponseProperties.HTTP_REASON_PROPERTY, HttpConstants.HttpStatus.MOVED_TEMPORARILY.getReasonPhrase());
        muleMessage.setOutboundProperty(HttpHeaders.Names.LOCATION, redirecturi);
    }

    private String cookieExtractor(String header, String cookieName) {
        if (header != null){
            return Arrays.stream(header.split(";"))
                    .filter(c -> c.split("=")[0].equals(cookieName))
                    .map(c -> c.split("=")[1])
                    .findFirst().orElse(null);
        } else return null;
    }
}
