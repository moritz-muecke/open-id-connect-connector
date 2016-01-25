package org.mule.modules.singlesignonoidc.config;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;

import javax.ws.rs.core.UriBuilder;

import org.mule.api.annotations.components.Configuration;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.display.Placement;
import org.mule.api.annotations.Configurable;
import org.mule.api.annotations.param.Default;
import org.mule.api.annotations.param.Optional;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

@Configuration(friendlyName = "Configuration")
public class ConnectorConfig {
	
	private OIDCProviderMetadata providerMetadata;
	private RSAPublicKey rsaPublicKey;
	private ClientSecretBasic clientSecretBasic;
	
	private URI introspectionUri;
	private URI ssoUri;
	
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
	 * Single Sign On Client ID
	 */
	@Configurable
	@FriendlyName("Client ID")
	private String clientId;
	
	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	
	/**
	 * Single Sign On Client Secret
	 */
	@Configurable
	@FriendlyName("Client Secret")
	private String clientSecret;

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
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
    @Default("/protocol/openid-connect/auth")
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
    @Default("/protocol/openid-connect/token")
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
    @Default("/protocol/openid-connect/certs")
    private String jwkSetEndpoint;
		
	public String getJwkSetEndpoint() {
		return jwkSetEndpoint;
	}

	public void setJwkSetEndpoint(String jwkSetEndpoint) {
		this.jwkSetEndpoint = jwkSetEndpoint;
	}

	public void buildSsoUri() {
		UriBuilder builder = UriBuilder
				.fromUri(ssoServerUrl)
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
	
	public void buildProviderMetadata() throws ParseException, JOSEException, java.text.ParseException {
		if(isConfigDiscovery()) {
			providerMetadata = OIDCProviderMetadataBuilder.provideMetadataFromServer(ssoUri, configDiscoveryEndpoint);
		} else providerMetadata = OIDCProviderMetadataBuilder.provideMetadataManually(ssoUri, authEndpoint, tokenEndpoint, jwkSetEndpoint);
		
		clientSecretBasic = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
		rsaPublicKey = OIDCProviderMetadataBuilder.providePublicKey(providerMetadata);
	}

	public OIDCProviderMetadata getProviderMetadata() {
		return providerMetadata;
	}

	public RSAPublicKey getRsaPublicKey() {
		return rsaPublicKey;
	}

	public URI getIntrospectionUri() {
		return introspectionUri;
	}

	public ClientSecretBasic getClientSecretBasic() {
		return clientSecretBasic;
	}

	public void setClientSecretBasic(ClientSecretBasic clientSecretBasic) {
		this.clientSecretBasic = clientSecretBasic;
	}
}