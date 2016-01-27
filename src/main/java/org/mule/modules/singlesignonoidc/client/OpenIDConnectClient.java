package org.mule.modules.singlesignonoidc.client;

import org.mule.modules.singlesignonoidc.config.ConnectorConfig;
import org.mule.modules.singlesignonoidc.config.ProviderMetaData;
import org.mule.modules.singlesignonoidc.exception.MetaDataInitializationException;
import org.mule.modules.singlesignonoidc.exception.TokenValidationException;


public class OpenIDConnectClient {
	
	private TokenValidator tokenValidator;
	private ProviderMetaData metaDataConfig;
	
	public OpenIDConnectClient(ConnectorConfig config) throws MetaDataInitializationException {
		metaDataConfig = new ProviderMetaData(config);
		metaDataConfig.buildSsoUri();
		try {
			metaDataConfig.buildProviderMetadata();
		} catch (Exception e) {
			throw new MetaDataInitializationException(e.getMessage());
		}
		tokenValidator = new TokenValidator(metaDataConfig);
	}
	
	public void tokenIntrospection(String authHeader, String clientId, String clientSecret, String introspectionEndpoint) throws TokenValidationException {
		metaDataConfig.buildIntrospectionUri(introspectionEndpoint);
		metaDataConfig.clientSecretBasicGenerator(clientId, clientSecret);
		tokenValidator.introspectionTokenValidation(authHeader);
	}
	
	public void localTokenValidation(String authHeader) throws TokenValidationException {
		tokenValidator.localTokenValidation(authHeader);
	}
}

