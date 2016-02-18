package org.mule.modules.oidctokenvalidator.client;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.apache.commons.httpclient.Cookie;
import org.mule.api.MuleContext;
import org.mule.api.MuleEvent;
import org.mule.api.MuleMessage;
import org.mule.api.store.ListableObjectStore;
import org.mule.api.store.ObjectStoreException;
import org.mule.module.http.api.HttpConstants.HttpStatus;
import org.mule.module.http.api.HttpConstants.ResponseProperties;
import org.mule.module.http.api.HttpHeaders;
import org.mule.modules.oidctokenvalidator.client.oidc.*;
import org.mule.modules.oidctokenvalidator.config.ConnectorConfig;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.HTTPConnectException;
import org.mule.modules.oidctokenvalidator.exception.MetaDataInitializationException;
import org.mule.modules.oidctokenvalidator.exception.RequestTokenFromSsoException;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;

public class OpenIdConnectClientImpl implements OpenIdConnectClient {
	
	private TokenValidator tokenValidator;
	private TokenStorage tokenStorage;
	private TokenRequester tokenRequester;
	private SingleSignOnConfig ssoConfig;
	private ConnectorConfig config;
	private final static String COOKIE_NAME = "MULE-OIDC-COOKIE";

	public OpenIdConnectClientImpl(ConnectorConfig connConfig, SingleSignOnConfig ssoCfg, TokenValidator validator, TokenRequester requester, TokenStorage storage) throws MetaDataInitializationException {
		ssoConfig = ssoCfg;
		config = connConfig;
		try {
			ssoConfig.buildProviderMetadata();
		} catch (Exception e) {
			throw new MetaDataInitializationException("Error during MetaData initilization from identity provider: " + e.getMessage());
		}
		tokenValidator = validator;
		tokenRequester = requester;
		tokenStorage = storage;
	}

    @Override
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

    @Override
	public Map<String, Object> localTokenValidation(String authHeader) throws TokenValidationException {
		JWTClaimsSet jwtClaimSet = tokenValidator.localTokenValidation(authHeader);
		return jwtClaimSet.toJSONObject();
	}

    @Override
	public boolean actAsRelyingParty(MuleMessage muleMessage) throws ObjectStoreException, RequestTokenFromSsoException {

        Map<String, String> queryParams = muleMessage.getInboundProperty("http.query.params");
		String cookieHeader = muleMessage.getInboundProperty("cookie");
        String authCode = queryParams.get("code");

        if (cookieHeader != null && cookieExtractor(cookieHeader) != null) {
			String tokens = tokenStorage.getTokens(cookieExtractor(cookieHeader));
            if (tokens == null && authCode != null) {
                retrieveAndStoreTokens(muleMessage, authCode);
            } else if (tokens == null) {
                setRedirectToSso(muleMessage);
                return false;
            }
        } else {
			if(authCode != null){
				retrieveAndStoreTokens(muleMessage, authCode);
			} else {
				setRedirectToSso(muleMessage);
                return false;
			}
		}
		return true;
	}

    @Override
    public SingleSignOnConfig getSsoConfig() {
        return ssoConfig;
    }

	private String cookieExtractor(String header) {
		return Arrays.stream(header.split(";"))
				.filter(c -> c.split("=")[0].equals(COOKIE_NAME))
				.map(c -> c.split("=")[1])
				.findFirst().orElse(null);
	}

    private MuleMessage setRedirectToSso(MuleMessage muleMessage) {
        muleMessage.setOutboundProperty(ResponseProperties.HTTP_STATUS_PROPERTY, HttpStatus.MOVED_TEMPORARILY.getStatusCode());
        muleMessage.setOutboundProperty(ResponseProperties.HTTP_REASON_PROPERTY, HttpStatus.MOVED_TEMPORARILY.getReasonPhrase());
        muleMessage.setOutboundProperty(HttpHeaders.Names.LOCATION, tokenRequester.buildRedirectUri());
        return muleMessage;
    }

    private MuleMessage retrieveAndStoreTokens(MuleMessage muleMessage, String authCode) throws ObjectStoreException, RequestTokenFromSsoException {
        OIDCTokens tokens = tokenRequester.requestTokensFromSso(authCode);
        String storageEntryId = UUID.randomUUID().toString();
        setTokenCookie(muleMessage, storageEntryId);
        tokenStorage.storeTokens(storageEntryId, tokens.toJSONObject().toJSONString());
        return muleMessage;
    }

    private MuleMessage setTokenCookie(MuleMessage muleMessage, String storageEntryId) {
        Cookie cookie = new Cookie("localhost:8080", COOKIE_NAME, storageEntryId);
        muleMessage.setOutboundProperty(HttpHeaders.Names.SET_COOKIE, cookie);
        return muleMessage;
    }

}