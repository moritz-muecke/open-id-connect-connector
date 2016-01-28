package org.mule.modules.singlesignonoidc.automation.unit;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mule.modules.singlesignonoidc.config.ConnectorConfig;
import org.mule.modules.singlesignonoidc.config.MetaDataProvider;
import org.mule.modules.singlesignonoidc.config.OIDCProviderMetaDataBuilder;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class MetaDataProviderTest extends Mockito{
	
	private Properties props;
	
	@Before
	public void init() throws Exception {
		props = new Properties();
		props.load(new FileReader(new File(this.getClass().getResource("unittest.properties").getPath())));
	}
	
	@Test
	public void buildProviderMetadataLocal() throws Exception {
		ConnectorConfig config = mock(ConnectorConfig.class);
		when(config.getSsoServerUrl()).thenReturn(props.getProperty("sso-url"));
		when(config.getSsoPort()).thenReturn(Integer.parseInt(props.getProperty("sso-port")));
		when(config.getSsoIssuerEndpoint()).thenReturn(props.getProperty("sso-issuer-endpoint"));
		when(config.getAuthEndpoint()).thenReturn(props.getProperty("sso-auth-endpoint"));
		when(config.getTokenEndpoint()).thenReturn(props.getProperty("sso-token-endpoint"));
		when(config.getJwkSetEndpoint()).thenReturn(props.getProperty("sso-jwk-set-endpoint"));
		when(config.isConfigDiscovery()).thenReturn(false);

		OIDCProviderMetaDataBuilder metaDataBuilder = mock(OIDCProviderMetaDataBuilder.class);
		when(metaDataBuilder.providePublicKey(Mockito.any(OIDCProviderMetadata.class))).thenReturn(getSampleRSAPublicKey());
		
		MetaDataProvider metaDataProvider = new MetaDataProvider(config);
		metaDataProvider.setMetaDataBuilder(metaDataBuilder);
		metaDataProvider.buildProviderMetadata();
		assertEquals(metaDataProvider.getRsaPublicKey(), getSampleRSAPublicKey());
	}
	
	private RSAPublicKey getSampleRSAPublicKey() throws Exception {
		String publicKeyString = props.getProperty("sso-public-key");
	    KeyFactory kFactory = KeyFactory.getInstance("RSA");  
        byte yourKey[] =  Base64.getDecoder().decode(publicKeyString.getBytes());
        X509EncodedKeySpec spec =  new X509EncodedKeySpec(yourKey);
        PublicKey publicKey = (PublicKey) kFactory.generatePublic(spec);
        return (RSAPublicKey)publicKey;
	}
}
