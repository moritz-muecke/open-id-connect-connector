package org.mule.modules.singlesignonoidc.config;

import org.mule.api.annotations.components.Configuration;
import org.mule.api.annotations.Configurable;
import org.mule.api.annotations.param.Default;

@Configuration(friendlyName = "Configuration")
public class ConnectorConfig {

    /**
     * SSO Server URI
     */
    @Configurable
    @Default("http://localhost:8080")
    private String ssoBasePath;

	public String getSsoBasePath() {
		return ssoBasePath;
	}
	
	public void setSsoBasePath(String ssoBasePath) {
		this.ssoBasePath = ssoBasePath;
	}
    
	
	/**
	 * SSO token validation endpoint
	 */
    @Configurable
    @Default("/auth/realms/master/tokens/validate")
    private String tokenValidationEndpoint;

	public String getTokenValidationEndpoint() {
		return tokenValidationEndpoint;
	}

	public void setTokenValidationEndpoint(String tokenValidationEndpoint) {
		this.tokenValidationEndpoint = tokenValidationEndpoint;
	}
    
    
}