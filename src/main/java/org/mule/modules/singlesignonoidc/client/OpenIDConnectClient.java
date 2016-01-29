package org.mule.modules.singlesignonoidc.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import org.mule.modules.singlesignonoidc.config.ConnectorConfig;
import org.mule.modules.singlesignonoidc.config.MetaDataProvider;
import org.mule.modules.singlesignonoidc.exception.HTTPConnectException;
import org.mule.modules.singlesignonoidc.exception.MetaDataInitializationException;
import org.mule.modules.singlesignonoidc.exception.TokenValidationException;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;


public class OpenIDConnectClient {
	
	private TokenValidator tokenValidator;
	private MetaDataProvider metaDataProvider;
	
	public OpenIDConnectClient(ConnectorConfig config) throws MetaDataInitializationException {
		metaDataProvider = new MetaDataProvider(config);
		try {
			metaDataProvider.buildProviderMetadata();
		} catch (Exception e) {
			throw new MetaDataInitializationException("Error during MetaData initilization from identity provider: " + e.getMessage());
		}
		tokenValidator = new TokenValidator(metaDataProvider);
	}
	
	public Map<String, Object> tokenIntrospection(String authHeader, String clientId, String clientSecret, String introspectionEndpoint) 
			throws TokenValidationException, HTTPConnectException {
		try {
			metaDataProvider.setIntrospectionUri(new URI(metaDataProvider.getSsoUri() + introspectionEndpoint));
		} catch (URISyntaxException e) {
			throw new TokenValidationException("Invalid introspection URL path");
		}
		metaDataProvider.setClientSecretBasic(new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)));
		return tokenValidator.introspectionTokenValidation(authHeader);
	}
	
	public Map<String, Object> localTokenValidation(String authHeader) throws TokenValidationException {
		JWTClaimsSet jwtClaimSet = tokenValidator.localTokenValidation(authHeader);
		return jwtClaimSet.toJSONObject();
	}
}

