package org.mule.modules.oidctokenvalidator.config;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;

import javax.ws.rs.core.UriBuilder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class SingleSignOnConfig {
	private OIDCProviderMetadata providerMetadata;
	private RSAPublicKey rsaPublicKey;
	private ClientSecretBasic clientSecretBasic;
	private String clientId;
	private String clientSecret;
	
	private URI introspectionUri;
	private URI ssoUri;
	
	private ConnectorConfig config;
	
	private OpenIDConnectMetaDataBuilder metaDataBuilder;
	
	public SingleSignOnConfig(ConnectorConfig config) {
		this.config = config;
		buildSsoUri();
		metaDataBuilder = new OpenIDConnectMetaDataBuilder(ssoUri);
	}
	
	public void buildSsoUri() {
		UriBuilder builder = UriBuilder
				.fromUri(config.getSsoServerUrl())
				.port(config.getSsoPort())
				.path(config.getSsoIssuerEndpoint());
		ssoUri = builder.build();
	}
	
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
}
