package org.mule.modules.singlesignonoidc.config;

import org.mule.api.annotations.Configurable;
import org.mule.api.annotations.components.Configuration;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.display.Placement;
import org.mule.api.annotations.param.Default;
import org.mule.api.annotations.param.Optional;

@Configuration(friendlyName = "Configuration")
public class ConnectorConfig {
	
	@Configurable
    @FriendlyName("SSO Server URL")
    @Default("http://localhost")
	private String ssoServerUrl;
    
	public String getSsoServerUrl() {
		return ssoServerUrl;
	}

	public void setSsoServerUrl(String ssoServerUrl) {
		this.ssoServerUrl = ssoServerUrl;
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
     * SSO OIDC endpoint
     */
    @Configurable
    @FriendlyName("SSO issuer endpoint")
    @Default("/auth/realms/master")
    private String ssoIssuerEndpoint;

	public String getSsoIssuerEndpoint() {
		return ssoIssuerEndpoint;
	}
	
	public void setSsoIssuerEndpoint(String ssoIssuerEndpoint) {
		this.ssoIssuerEndpoint = ssoIssuerEndpoint;
	}
	
	/**
	 * Endpoint to retrieve OP configuration
	 */
	@Configurable
	@FriendlyName("OpenID Configuration discovery endpoint")
	@Default("/.well-known/openid-configuration")
	private String configDiscoveryEndpoint;
	
	
	public String getConfigDiscoveryEndpoint() {
		return configDiscoveryEndpoint;
	}

	public void setConfigDiscoveryEndpoint(String configDiscoveryEndpoint) {
		this.configDiscoveryEndpoint = configDiscoveryEndpoint;
	}

	/**
	 * Enables or disables OpenID Configuration discovery
	 */
	@Configurable
	@FriendlyName("OpenID Configuration discovery")
	@Default("false")
	private boolean configDiscovery;
	
	public boolean isConfigDiscovery() {
		return configDiscovery;
	}

	public void setConfigDiscovery(boolean configDiscovery) {
		this.configDiscovery = configDiscovery;
	}
	
	/**
	 *Authorization endpoint. HINT: This is a optional parameter if OpenID Configuration discovery is active
	 */
	@Configurable
	@Optional
	@FriendlyName("Authorization endpoint")
	@Placement(tab="Manual Configuration", group="Endpoints", order = 0)
	private String authEndpoint;
	
	public String getAuthEndpoint() {
		return authEndpoint;
	}

	public void setAuthEndpoint(String authEndpoint) {
		this.authEndpoint = authEndpoint;
	}
	
	/**
	 *Token endpoint. HINT: This is a optional parameter if OpenID Configuration discovery is active
	 */
	@Configurable
	@Optional
	@FriendlyName("Token endpoint")
	@Placement(tab="Manual Configuration", group="Endpoints", order = 1)
	private String tokenEndpoint;
	
	public String getTokenEndpoint() {
		return tokenEndpoint;
	}

	public void setTokenEndpoint(String tokenEndpoint) {
		this.tokenEndpoint = tokenEndpoint;
	}

	/**
	 * JWK-Set endpoint. HINT: This is a optional parameter if OpenID Configuration discovery is active
	 */
	@Configurable
	@Optional
	@FriendlyName("JWK-Set endpoint")
	@Placement(tab="Manual Configuration", group="Endpoints", order = 2)
    private String jwkSetEndpoint;
		
	public String getJwkSetEndpoint() {
		return jwkSetEndpoint;
	}

	public void setJwkSetEndpoint(String jwkSetEndpoint) {
		this.jwkSetEndpoint = jwkSetEndpoint;
	}
}