package org.mule.modules.singlesignonoidc.client;

import java.net.URI;
import java.net.URISyntaxException;

import org.mule.modules.singlesignonoidc.config.ConnectorConfig;
import org.mule.modules.singlesignonoidc.config.MetaDataProvider;
import org.mule.modules.singlesignonoidc.exception.MetaDataInitializationException;
import org.mule.modules.singlesignonoidc.exception.TokenValidationException;

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
			throw new MetaDataInitializationException("Could not connect to SSO. Error: " + e.getMessage());
		}
		tokenValidator = new TokenValidator(metaDataProvider);
	}
	
	public void tokenIntrospection(String authHeader, String clientId, String clientSecret, String introspectionEndpoint) throws TokenValidationException {
		try {
			metaDataProvider.setIntrospectionUri(new URI(metaDataProvider.getSsoUri() + introspectionEndpoint));
		} catch (URISyntaxException e) {
			throw new TokenValidationException("Invalid introspection URL path");
		}
		metaDataProvider.setClientSecretBasic(new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)));
		tokenValidator.introspectionTokenValidation(authHeader);
	}
	
	public void localTokenValidation(String authHeader) throws TokenValidationException {
		tokenValidator.localTokenValidation(authHeader);
	}
}

