package org.mule.modules.singlesignonoidc.config;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;

import javax.ws.rs.core.UriBuilder;

import org.mule.modules.singlesignonoidc.exception.MetaDataInitializationException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class ProviderMetaData {
	private OIDCProviderMetadata providerMetadata;
	private RSAPublicKey rsaPublicKey;
	private ClientSecretBasic clientSecretBasic;
	private String clientId;
	private String clientSecret;
	
	private URI introspectionUri;
	private URI ssoUri;
	
	private ConnectorConfig config;
	
	private OIDCProviderMetaDataBuilder metaDataBuilder;
	
	public ProviderMetaData(ConnectorConfig config) {
		this.config = config;
	}
	
	public void buildSsoUri() {
		UriBuilder builder = UriBuilder
				.fromUri(config.getSsoServerUrl())
				.port(config.getSsoPort())
				.path(config.getSsoIssuerEndpoint());
		ssoUri = builder.build();
	}
	
	public void buildIntrospectionUri(String introspectionEndpoint) {
		UriBuilder builder = UriBuilder
				.fromUri(ssoUri)
				.path(introspectionEndpoint);
		introspectionUri = builder.build();
	}
	
	public void buildProviderMetadata() throws ParseException, JOSEException, java.text.ParseException {

		metaDataBuilder = new OIDCProviderMetaDataBuilder(ssoUri);
		
		if(config.isConfigDiscovery()) {
			providerMetadata = metaDataBuilder.provideMetadataFromServer(config.getConfigDiscoveryEndpoint());
		} else providerMetadata = metaDataBuilder.provideMetadataManually(config.getAuthEndpoint(), config.getTokenEndpoint(), config.getJwkSetEndpoint());
		
		rsaPublicKey = metaDataBuilder.providePublicKey(providerMetadata);
		
	}

	public void clientSecretBasicGenerator(String clientId, String clientSecret){
		clientSecretBasic = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
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
}
