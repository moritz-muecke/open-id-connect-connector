package org.mule.modules.oidctokenvalidator.config;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;

import javax.ws.rs.core.UriBuilder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * This config extends the ConnectorConfig with several fields and parameters which
 * are needed for the communication with the SingleSignOn Server
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class SingleSignOnConfig {
	private OIDCProviderMetadata providerMetadata;
	private RSAPublicKey rsaPublicKey;
	private ClientSecretBasic clientSecretBasic;
	private String clientId;
	private String clientSecret;
	private URI redirectUri;
	private URI introspectionUri;
	private URI ssoUri;
	
	private ConnectorConfig config;
	
	private OpenIDConnectMetaDataBuilder metaDataBuilder;
	
	public SingleSignOnConfig(ConnectorConfig config) {
		this.config = config;
		UriBuilder builder = UriBuilder
				.fromUri(config.getSsoServerUrl())
				.port(config.getSsoPort())
				.path(config.getSsoIssuerEndpoint());
		this.ssoUri = builder.build();
		this.metaDataBuilder = new OpenIDConnectMetaDataBuilder(ssoUri);
	}

	/**
	 * Depending on the config discovery parameter, this method builds the
     * Identity-Provider meta data. If config discovery is enabled, it calls an HTTP
     * endpoint at the IdP to collect the needed information. Otherwise it extracts
     * the information out of the ConnectorConfig.
     * If one of the exceptions occurs, the mule flow is intercepted because the
     * connector can not work correctly without the IdP meta data.
     *
	 * @throws ParseException
	 * @throws JOSEException
	 * @throws java.text.ParseException
     */
	public void buildProviderMetadata() throws ParseException, JOSEException, java.text.ParseException {
		if(config.isConfigDiscovery()) {
			providerMetadata = metaDataBuilder.provideMetadataFromServer(config.getConfigDiscoveryEndpoint());
		} else providerMetadata = metaDataBuilder.provideMetadataManually(config.getAuthEndpoint(), config.getTokenEndpoint(), config.getJwkSetEndpoint());
		
		rsaPublicKey = metaDataBuilder.providePublicKey(providerMetadata);
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

	public void setIntrospectionUri(URI introspectionUri) {
		this.introspectionUri = introspectionUri;
	}

	public ClientSecretBasic getClientSecretBasic() {
		return clientSecretBasic;
	}

	public void setClientSecretBasic(ClientSecretBasic clientSecretBasic) {
		this.clientSecretBasic = clientSecretBasic;
	}

	public URI getSsoUri() {
		return ssoUri;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public void setMetaDataBuilder(OpenIDConnectMetaDataBuilder metaDataBuilder) {
		this.metaDataBuilder = metaDataBuilder;
	}

	public URI getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(URI redirectUri) {
		this.redirectUri = redirectUri;
	}
}
