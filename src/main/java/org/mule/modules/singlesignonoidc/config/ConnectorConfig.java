package org.mule.modules.singlesignonoidc.config;

import org.mule.api.annotations.components.Configuration;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.Configurable;
import org.mule.api.annotations.param.Default;

@Configuration(friendlyName = "Configuration")
public class ConnectorConfig {

    /**
     * SSO Server URI
     */
    @Configurable
    @FriendlyName("SSO base path")
    @Default("http://localhost")
    private String ssoBasePath;

	public String getSsoBasePath() {
		return ssoBasePath;
	}
	
	public void setSsoBasePath(String ssoBasePath) {
		this.ssoBasePath = ssoBasePath;
	}
	
	/**
     * SSO Server port
     */
	@Configurable
	@FriendlyName("SSO port number")
	@Default("8080")
	private int ssoPort;
	
	public int getSsoPort() {
		return ssoPort;
	}

	public void setSsoPort(int ssoPort) {
		this.ssoPort = ssoPort;
	}

	/**
	 * Enables or disables token storage
	 */
	@Configurable
	@FriendlyName("Token storage")
	@Default("false")
	private boolean tokenStorage;
	
	public boolean isTokenStorage() {
		return tokenStorage;
	}

	public void setTokenStorage(boolean tokenStorage) {
		this.tokenStorage = tokenStorage;
	}

	/**
	 * Token introspection endpoint
	 */
    @Configurable
    @FriendlyName("Token-Introspection endpoint")
    @Default("/auth/realms/master/tokens/validate")
    private String tokenIntrospectionEndpoint;

	public String getTokenIntrospectionEndpoint() {
		return tokenIntrospectionEndpoint;
	}

	public void setTokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
		this.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint;
	}
    
    
}