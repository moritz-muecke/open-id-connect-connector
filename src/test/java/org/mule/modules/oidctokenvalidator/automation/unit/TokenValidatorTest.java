package org.mule.modules.oidctokenvalidator.automation.unit;

import static org.junit.Assert.assertEquals;

import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mule.modules.oidctokenvalidator.client.tokenvalidation.TokenVerifier;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest(TokenVerifier.class)
public class TokenValidatorTest extends Mockito{
	/*
	private Properties props;
		
	@Before
	public void init() throws Exception {
		props = new Properties();
		props.load(new FileReader(new File(this.getClass().getResource("unittest.properties").getPath())));
	}
	
	@Test
	public void introspectionTokenValidationShouldReturnTokenClaims() throws Exception {
		SingleSignOnConfig metaDataProvider = mock(SingleSignOnConfig.class);
		TokenValidator tokenValidator = spy(new TokenValidator(metaDataProvider));
		
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setContent("{\"name\":\"John Doe\", \"active\":true}");
		
		HTTPRequest httpRequest = mock(HTTPRequest.class);
		when(httpRequest.send()).thenReturn(httpResponse);

		TokenIntrospectionRequest introspectionRequest = mock(TokenIntrospectionRequest.class);
		when(introspectionRequest.toHTTPRequest()).thenReturn(httpRequest);
		doReturn(introspectionRequest).when(tokenValidator).createTokenIntrospectionRequest(Mockito.any(AccessToken.class));
		
		JSONObject claims = tokenValidator.introspectionTokenValidation(props.getProperty("bearer-auth-header"));
	
		verify(httpRequest).send();
		verify(introspectionRequest).toHTTPRequest();
		
		assertEquals(claims.get("active"), true);
		assertEquals(claims.get("name"), "John Doe");
	}
	
	@Test
	public void localTokenValidationShouldReturnTokenClaims() throws Exception {
		PowerMockito.mockStatic(TokenVerifier.class);
		
		JSONObject json = new JSONObject();
		json.put("iss", props.getProperty("sso-url"));
		json.put("exp", System.currentTimeMillis() + 10000);
		json.put("nbf", 0);
		JWTClaimsSet givenClaims = JWTClaimsSet.parse(json);
		
		SingleSignOnConfig metaDataProvider = mock(SingleSignOnConfig.class);
		when(metaDataProvider.getRsaPublicKey()).thenReturn((RSAPublicKey)RSAKeyGenerator.keyPairGenerator().getPublic());
		when(metaDataProvider.getSsoUri()).thenReturn(new URI(props.getProperty("sso-url")));

		Mockito.when(TokenVerifier.verifyAccessToken(
				Mockito.any(JWSVerifier.class), 
				Mockito.any(SignedJWT.class), 
				Mockito.any(String.class))).thenReturn(givenClaims);
		
		TokenValidator tokenValidator = new TokenValidator(metaDataProvider);
		JWTClaimsSet expectedClaims = tokenValidator.localTokenValidation(props.getProperty("bearer-auth-header"));
		PowerMockito.verifyStatic();
		assertEquals(givenClaims.getClaims(), expectedClaims.getClaims());
	}
	*/
}
