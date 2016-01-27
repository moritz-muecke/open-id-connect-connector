package org.mule.modules.singlesignonoidc.automation.unit;

import static org.junit.Assert.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mule.modules.singlesignonoidc.config.OIDCProviderMetaDataBuilder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class OIDCProviderMetaDataBuilderTest extends Mockito{

	String serverUrl;
	URI serverUri;
	String authEndpoint;
	String tokenEndpoint;
	String jwkSetEndpoint;
	String configEndpoint;
	OIDCProviderMetadata testMetaData;
	OIDCProviderMetadata wrongTestMetaData;
		
	@Before
	public void init() throws URISyntaxException{
		serverUrl = "http://localhost:8080";
		serverUri = new URI(serverUrl);
		authEndpoint = "/auth";
		tokenEndpoint = "/token";
		jwkSetEndpoint = "/certs";
		configEndpoint = "/.well-known/openid-configuration";
		
		Issuer issuer = new Issuer(new URI(serverUrl));
		URI authUri = new URI(serverUrl + authEndpoint);
		URI tokenUri = new URI(serverUrl + tokenEndpoint);
		URI jwkSetUri = new URI(serverUrl + jwkSetEndpoint);
        List<SubjectType> subjectTypes = new ArrayList<>();
        subjectTypes.add(SubjectType.PUBLIC);
		
		testMetaData = new OIDCProviderMetadata(issuer, subjectTypes, jwkSetUri);
        testMetaData.setAuthorizationEndpointURI(authUri);
        testMetaData.setTokenEndpointURI(tokenUri);
        testMetaData.applyDefaults();
        
        wrongTestMetaData = new OIDCProviderMetadata(issuer, subjectTypes, jwkSetUri);
	}
	
	
	
	@Test
	public void provideMetadataManuallyShouldReturnMetaData() {
        OIDCProviderMetaDataBuilder metaDataBuilder = new OIDCProviderMetaDataBuilder(serverUri);
		OIDCProviderMetadata createdMetaData = metaDataBuilder.provideMetadataManually(authEndpoint, tokenEndpoint, jwkSetEndpoint);
        
        assertEquals(testMetaData.getClaims(), createdMetaData.getClaims());
	}
	
	@Test
	public void provideMetadataFromServerShouldReturnMetaData() throws ParseException {
		OIDCProviderMetaDataBuilder metaDataBuilder = Mockito.mock(OIDCProviderMetaDataBuilder.class);
		when(metaDataBuilder.provideMetadataFromServer(configEndpoint)).thenReturn(testMetaData);
		assertEquals(metaDataBuilder.provideMetadataFromServer(configEndpoint), testMetaData);
	}
	
	@Test(expected=ParseException.class)
	public void provideMetadataFromServerShouldThrowParseException() throws ParseException {
		OIDCProviderMetaDataBuilder metaDataBuilder = Mockito.mock(OIDCProviderMetaDataBuilder.class);
		doThrow(new ParseException("Could not parse JSON response")).when(metaDataBuilder).provideMetadataFromServer("/wrong-endpoint");
		metaDataBuilder.provideMetadataFromServer("/wrong-endpoint");
	}
	
	@Test
	public void providePublicKeyShouldReturnRSAPublicKey() throws Exception {
		OIDCProviderMetaDataBuilder metaDataBuilder = Mockito.mock(OIDCProviderMetaDataBuilder.class);
		RSAPublicKey rsaPublicKey = Mockito.mock(RSAPublicKey.class);
		when(metaDataBuilder.providePublicKey(testMetaData)).thenReturn(rsaPublicKey);
		assertEquals(metaDataBuilder.providePublicKey(testMetaData), rsaPublicKey);
	}
	
	@Test(expected=ParseException.class)
	public void providePublicKeyShouldThrowException() throws ParseException, JOSEException, java.text.ParseException  {
		OIDCProviderMetaDataBuilder metaDataBuilder = Mockito.mock(OIDCProviderMetaDataBuilder.class);
		doThrow(new ParseException("Could not parse JSON response")).when(metaDataBuilder).providePublicKey(wrongTestMetaData);
		metaDataBuilder.providePublicKey(wrongTestMetaData);
	}
	
}
