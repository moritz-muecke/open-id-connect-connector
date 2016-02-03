package org.mule.modules.oidctokenvalidator.automation.unit;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileReader;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.Properties;

import net.minidev.json.JSONObject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mule.modules.oidctokenvalidator.automation.unit.util.RSAKeyGenerator;
import org.mule.modules.oidctokenvalidator.client.oidc.SignedTokenVerifier;
import org.mule.modules.oidctokenvalidator.client.oidc.TokenValidator;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;

@RunWith(PowerMockRunner.class)
@PrepareForTest(SignedTokenVerifier.class)
public class TokenValidatorTest extends Mockito{
	
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
		PowerMockito.mockStatic(SignedTokenVerifier.class);
		
		JSONObject json = new JSONObject();
		json.put("iss", props.getProperty("sso-url"));
		json.put("exp", System.currentTimeMillis() + 10000);
		json.put("nbf", 0);
		JWTClaimsSet givenClaims = JWTClaimsSet.parse(json);
		
		SingleSignOnConfig metaDataProvider = mock(SingleSignOnConfig.class);
		when(metaDataProvider.getRsaPublicKey()).thenReturn((RSAPublicKey)RSAKeyGenerator.keyPairGenerator().getPublic());
		when(metaDataProvider.getSsoUri()).thenReturn(new URI(props.getProperty("sso-url")));

		Mockito.when(SignedTokenVerifier.verifyToken(
				Mockito.any(JWSVerifier.class), 
				Mockito.any(SignedJWT.class), 
				Mockito.any(String.class))).thenReturn(givenClaims);
		
		TokenValidator tokenValidator = new TokenValidator(metaDataProvider);
		JWTClaimsSet expectedClaims = tokenValidator.localTokenValidation(props.getProperty("bearer-auth-header"));
		PowerMockito.verifyStatic();
		assertEquals(givenClaims.getClaims(), expectedClaims.getClaims());
	}
}
