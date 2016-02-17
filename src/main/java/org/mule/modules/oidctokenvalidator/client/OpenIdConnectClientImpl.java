package org.mule.modules.oidctokenvalidator.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Map;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.mule.api.MuleMessage;
import org.mule.module.http.api.HttpConstants.HttpStatus;
import org.mule.module.http.api.HttpConstants.ResponseProperties;
import org.mule.module.http.api.HttpHeaders;
import org.mule.modules.oidctokenvalidator.client.oidc.*;
import org.mule.modules.oidctokenvalidator.config.ConnectorConfig;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.HTTPConnectException;
import org.mule.modules.oidctokenvalidator.exception.MetaDataInitializationException;
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

	public MuleMessage actAsRelyingParty(MuleMessage muleMessage) {
		String cookieHeader = muleMessage.getInboundProperty("cookie");
		if (cookieExtractor(cookieHeader) != null) {
			OIDCTokens tokens = tokenStorage.getTokens(cookieExtractor(cookieHeader));
			// TODO: Validate token
		} else {
			Map<String, String> queryParams = muleMessage.getInboundProperty("http.query.params");
			if(queryParams.get("code") != null){
				OIDCTokens tokens = tokenRequester.requestTokensFromSso(queryParams.get("code"));
				// TODO: Validate token & set cookie
				String storageId = tokenStorage.storeTokens(tokens);
			} else {
				muleMessage.setOutboundProperty(ResponseProperties.HTTP_STATUS_PROPERTY, HttpStatus.MOVED_TEMPORARILY.getStatusCode());
				muleMessage.setOutboundProperty(ResponseProperties.HTTP_REASON_PROPERTY, HttpStatus.MOVED_TEMPORARILY.getReasonPhrase());
				muleMessage.setOutboundProperty(HttpHeaders.Names.LOCATION, tokenRequester.buildRedirectUri(ssoConfig));
			}
		}
		return muleMessage;
	}

	private String cookieExtractor(String header) {
		return Arrays.stream(header.split(";"))
				.filter(c -> c.split("=")[0].equals(COOKIE_NAME))
				.map(c -> c.split("=")[1])
				.findFirst().orElse(null);
	}
}

