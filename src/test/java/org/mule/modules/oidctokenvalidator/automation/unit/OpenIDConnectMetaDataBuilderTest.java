package org.mule.modules.oidctokenvalidator.automation.unit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileReader;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.tools.ant.types.CommandlineJava.SysProperties;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mule.modules.oidctokenvalidator.config.OpenIDConnectMetaDataBuilder;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class OpenIDConnectMetaDataBuilderTest extends Mockito{

	private Properties props;	
	
	@Before
	public void init() throws Exception{
		props = new Properties();
		props.load(new FileReader(new File(this.getClass().getResource("unittest.properties").getPath()))); 
	}
	/*
	@Test
	public void provideMetadataManuallyShouldReturnMetaData() throws Exception{
        OpenIDConnectMetaDataBuilder metaDataBuilder = new OpenIDConnectMetaDataBuilder(new URI(props.getProperty("sso-url")));
		OIDCProviderMetadata providerMetaData = metaDataBuilder.provideMetadataManually(
				props.getProperty("sso-auth-endpoint"), 
				props.getProperty("sso-token-endpoint"),
				props.getProperty("sso-jwk-set-endpoint"));
        
		assertTrue(providerMetaData.getAuthorizationEndpointURI().toString()
				.equals(props.getProperty("sso-url") + props.getProperty("sso-auth-endpoint")));
        assertTrue(providerMetaData.getIssuer().getValue()
        		.equals(props.getProperty("sso-url")));
        assertTrue(providerMetaData.getJWKSetURI().toString()
        		.equals(props.getProperty("sso-url") + props.getProperty("sso-jwk-set-endpoint")));
	}
	
	@Test
	public void provideMetadataFromServerShouldReturnMetaData() throws Exception {
		List<SubjectType> subjectTypes = new ArrayList<>();
        subjectTypes.add(SubjectType.PUBLIC);
		OIDCProviderMetadata testMetaData = new OIDCProviderMetadata(
				new Issuer(props.getProperty("sso-url")), 
				subjectTypes, 
				new URI(props.getProperty("sso-jwk-set-endpoint")));
		OpenIDConnectMetaDataBuilder metaDataBuilder = Mockito.mock(OpenIDConnectMetaDataBuilder.class);
		when(metaDataBuilder.provideMetadataFromServer(props.getProperty("sso-config-endpoint"))).thenReturn(testMetaData);
		assertEquals(metaDataBuilder.provideMetadataFromServer(props.getProperty("sso-config-endpoint")), testMetaData);
	}
	
	@Test(expected=ParseException.class)
	public void provideMetadataFromServerShouldThrowParseException() throws ParseException {
		OpenIDConnectMetaDataBuilder metaDataBuilder = Mockito.mock(OpenIDConnectMetaDataBuilder.class);
		doThrow(new ParseException("Could not parse JSON response")).when(metaDataBuilder).provideMetadataFromServer("/wrong-endpoint");
		metaDataBuilder.provideMetadataFromServer("/wrong-endpoint");
	}
	
	@Test
	public void providePublicKeyShouldReturnRSAPublicKey() throws Exception {
		OpenIDConnectMetaDataBuilder metaDataBuilder = Mockito.mock(OpenIDConnectMetaDataBuilder.class);
		RSAPublicKey rsaPublicKey = Mockito.mock(RSAPublicKey.class);
		when(metaDataBuilder.providePublicKey(Mockito.any(OIDCProviderMetadata.class))).thenReturn(rsaPublicKey);
		assertEquals(metaDataBuilder.providePublicKey(Mockito.any(OIDCProviderMetadata.class)), rsaPublicKey);
	}
	
	@Test(expected=ParseException.class)
	public void providePublicKeyShouldThrowException() throws Exception  {
		List<SubjectType> subjectTypes = new ArrayList<>();
        subjectTypes.add(SubjectType.PUBLIC);
		OIDCProviderMetadata invalidMetaData = new OIDCProviderMetadata(
				new Issuer(props.getProperty("sso-url")), 
				subjectTypes, 
				new URI("wrong-config-endoint"));
		OpenIDConnectMetaDataBuilder metaDataBuilder = Mockito.mock(OpenIDConnectMetaDataBuilder.class);
		doThrow(new ParseException("Could not parse JSON response")).when(metaDataBuilder).providePublicKey(invalidMetaData);
		metaDataBuilder.providePublicKey(invalidMetaData);
	}
	*/
}
