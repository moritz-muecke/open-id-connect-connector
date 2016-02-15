package org.mule.modules.oidctokenvalidator.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.mule.api.MuleMessage;
import org.mule.modules.oidctokenvalidator.client.oidc.TokenValidator;
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
	private SingleSignOnConfig metaDataProvider;
	private ConnectorConfig config;
	
	public OpenIdConnectClientImpl(ConnectorConfig config) throws MetaDataInitializationException {
		this.config = config;
		metaDataProvider = new SingleSignOnConfig(this.config);
		try {
			metaDataProvider.buildProviderMetadata();
		} catch (Exception e) {
			throw new MetaDataInitializationException("Error during MetaData initilization from identity provider: " + e.getMessage());
		}
		tokenValidator = new TokenValidator(metaDataProvider);
	}
	
	public Map<String, Object> ssoTokenValidation(String authHeader) 
			throws TokenValidationException, HTTPConnectException {
		try {
			metaDataProvider.setIntrospectionUri(new URI(metaDataProvider.getSsoUri() + config.getIntrospectionEndpoint()));
		} catch (URISyntaxException e) {
			throw new TokenValidationException("Invalid introspection URL path");
		}
		metaDataProvider.setClientSecretBasic(new ClientSecretBasic(new ClientID(config.getClientId()), new Secret(config.getClientSecret())));
		return tokenValidator.introspectionTokenValidation(authHeader);
	}
	
	public Map<String, Object> localTokenValidation(String authHeader) throws TokenValidationException {
		JWTClaimsSet jwtClaimSet = tokenValidator.localTokenValidation(authHeader);
		return jwtClaimSet.toJSONObject();
	}

	public MuleMessage actAsRelyingParty(MuleMessage muleMessage) {
		return null;
	}
}

