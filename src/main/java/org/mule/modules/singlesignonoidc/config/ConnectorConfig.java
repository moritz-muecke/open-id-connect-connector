package org.mule.modules.singlesignonoidc.config;

import org.mule.api.annotations.components.Configuration;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.display.Placement;
import org.mule.api.annotations.display.Summary;
import org.mule.api.annotations.Configurable;
import org.mule.api.annotations.param.Default;
import org.mule.extension.annotations.param.Optional;

@Configuration(friendlyName = "Configuration")
public class ConnectorConfig {

	@Configurable
	@Summary("Main file documentation explaining what the impex file contains.")
	@Placement(tab = "Details", order = 1)
	@Optional
	private String TestString;
	
	
    public String getTestString() {
		return TestString;
	}

	public void setTestString(String testString) {
		TestString = testString;
	}

	@Configurable
    @FriendlyName("SSO URI")
    @Default("http://localhost")
	private String ssoUri;
    
	public String getSsoUri() {
		return ssoUri;
	}

	public void setSsoUri(String ssoUri) {
		this.ssoUri = ssoUri;
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
     * SSO OIDC base path
     */
    @Configurable
    @FriendlyName("SSO base path")
    @Default("/auth")
    private String ssoBasePath;

	public String getSsoBasePath() {
		return ssoBasePath;
	}
	
	public void setSsoBasePath(String ssoBasePath) {
		this.ssoBasePath = ssoBasePath;
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
    @Default("/realms/master/tokens/validate")
    private String tokenIntrospectionEndpoint;

	public String getTokenIntrospectionEndpoint() {
		return tokenIntrospectionEndpoint;
	}

	public void setTokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
		this.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint;
	}
    
    
}