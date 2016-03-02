package org.mule.modules.oidctokenvalidator.automation.unit;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class SignedTokenVerifierTest {
	/*
	private KeyPair keyPair;
	private JWSVerifier verifier;
	private JWSSigner signer;
	private JSONObject json;
	private Properties props;
	
	
	@Before
	public void init() throws Exception {
		keyPair = RSAKeyGenerator.keyPairGenerator();
		verifier = new RSASSAVerifier((RSAPublicKey)keyPair.getPublic());
		signer = new RSASSASigner((RSAPrivateKey)keyPair.getPrivate());
		json = new JSONObject();
		props = new Properties();
		props.load(new FileReader(new File(this.getClass().getResource("unittest.properties").getPath())));
	}
	
	@Test
	public void isActiveShouldReturnTrue() throws Exception {
		assertTrue(TokenVerifier.isActive(System.currentTimeMillis() + 10000, System.currentTimeMillis() - 10000));
	}
	
	@Test
	public void isActiveShouldReturnFalse() throws Exception {
		assertFalse(TokenVerifier.isActive(System.currentTimeMillis() - 10000, System.currentTimeMillis() + 10000));
	}
	
	@Test(expected=TokenValidationException.class)
	public void verifyTokenShouldThrowTokenValidationException() throws Exception{
		json.put("iss", props.getProperty("sso-url"));
		json.put("exp", 0);
		json.put("nbf", 0);
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), JWTClaimsSet.parse(json));
		jwt.sign(signer);
		TokenVerifier.verifyAccessToken(verifier, jwt, props.getProperty("sso-url"));
	}
	
	@Test
	public void verifyTokenShouldReturnClaimSet() throws Exception{
		json.put("iss", props.getProperty("sso-url"));
		json.put("exp", System.currentTimeMillis() + 10000);
		json.put("nbf", 0);
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS512), JWTClaimsSet.parse(json));
		jwt.sign(signer);
		assertTrue(TokenVerifier.verifyAccessToken(verifier, jwt, props.getProperty("sso-url")) instanceof JWTClaimsSet);
	}
	*/
}
