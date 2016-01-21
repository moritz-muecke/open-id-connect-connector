package org.mule.modules.singlesignonoidc.config;

import java.net.URI;

import javax.ws.rs.core.UriBuilder;

import org.mule.api.annotations.components.Configuration;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.Configurable;
import org.mule.api.annotations.param.Default;

@Configuration(friendlyName = "Configuration")
public class ConnectorConfig {
	
	private URI introspectionUri;
	private URI ssoUri;
	
	@Configurable
    @FriendlyName("SSO Path")
    @Default("http://localhost")
	private String ssoPath;
    
	public String getSsoPath() {
		return ssoPath;
	}

	public void setSsoPath(String ssoPath) {
		this.ssoPath = ssoPath;
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
     * SSO puplic key
     */
    @Configurable
    @FriendlyName("SSO puplic key")
    private String ssoPublicKey;
	
	public String getSsoPublicKey() {
		return ssoPublicKey;
	}

	public void setSsoPublicKey(String ssoPublicKey) {
		this.ssoPublicKey = ssoPublicKey;
	}

	/**
	 * Enables or disables OpenID Provider discovery
	 */
	@Configurable
	@FriendlyName("OpenID Provider discovery")
	@Default("false")
	private boolean opDiscovery;
	
	public boolean isOpDiscovery() {
		return opDiscovery;
	}

	public void setOpDiscovery(boolean opDiscovery) {
		this.opDiscovery = opDiscovery;
	}
	
	
	/**
	 * Enables or disables Open ID Connect Authorization Code Flow
	 */
	@Configurable
	@FriendlyName("Authorization Code Flow")
	@Default("false")
	private boolean authCodeFlow;
	
	public boolean isAuthCodeFlow() {
		return authCodeFlow;
	}

	public void setAuthCodeFlow(boolean authCodeFlow) {
		this.authCodeFlow = authCodeFlow;
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

	public void buildSsoUri() {
		UriBuilder builder = UriBuilder
				.fromUri(ssoPath)
				.port(ssoPort)
				.path(ssoIssuerEndpoint);
		ssoUri = builder.build();
	}
	
	public void buildIntrospectionUri(String introspectionEndpoint) {
		UriBuilder builder = UriBuilder
				.fromUri(ssoUri)
				.path(introspectionEndpoint);
		introspectionUri = builder.build();
	}

	public URI getIntrospectionUri() {
		return introspectionUri;
	}

	public URI getSsoUri() {
		return ssoUri;
	}
    
	
}