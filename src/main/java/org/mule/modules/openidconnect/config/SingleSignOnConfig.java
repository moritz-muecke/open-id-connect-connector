/**
 * Copyright 2016 Moritz Möller, AOE GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mule.modules.openidconnect.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.mule.modules.openidconnect.exception.MetaDataInitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;

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
	private boolean isInitialized = false;
	
	private ConnectorConfig config;
	
	private MetaDataBuilder metaDataBuilder;

	private static final Logger logger = LoggerFactory.getLogger(SingleSignOnConfig.class);


	public SingleSignOnConfig(ConnectorConfig config) {
		this.config = config;
		UriBuilder builder = UriBuilder
				.fromUri(config.getSsoServerUrl())
				.port(config.getSsoPort())
				.path(config.getSsoIssuerEndpoint());
		this.ssoUri = builder.build();
		this.metaDataBuilder = new MetaDataBuilder(ssoUri);
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
	public void buildProviderMetadata() throws MetaDataInitializationException {
		try {
			if(config.isConfigDiscovery()) {
                providerMetadata = metaDataBuilder.provideMetadataFromServer(config.getConfigDiscoveryEndpoint());
				rsaPublicKey = metaDataBuilder.providePublicKeyFromJwkSet(providerMetadata);
            } else {
				providerMetadata = metaDataBuilder.provideMetadataManually(
						config.getAuthEndpoint(), config.getTokenEndpoint(), config.getJwkSetEndpoint()
				);
				rsaPublicKey = metaDataBuilder.providePublicKeyFromString(config.getPublicKey());
			}

            isInitialized = true;
        } catch (Exception e) {
			logger.debug("Error occurred while building identity provider meta data. Exception: {}, Message: {}",
					e.getCause(), e.getMessage());
			throw new MetaDataInitializationException(
					String.format("Error during metadata initialization. Reason: %s", e.getMessage())
            );
        }
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

	public void setMetaDataBuilder(MetaDataBuilder metaDataBuilder) {
		this.metaDataBuilder = metaDataBuilder;
	}

	public URI getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(URI redirectUri) {
		this.redirectUri = redirectUri;
	}

	public boolean isInitialized() {
		return isInitialized;
	}

	public void setInitialized(boolean initialized) {
		isInitialized = initialized;
	}
}
