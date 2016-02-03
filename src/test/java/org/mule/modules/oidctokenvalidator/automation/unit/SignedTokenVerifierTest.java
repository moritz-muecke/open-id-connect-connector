package org.mule.modules.oidctokenvalidator.automation.unit;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Properties;

import net.minidev.json.JSONObject;

import org.junit.Before;
import org.junit.Test;
import org.mule.modules.oidctokenvalidator.automation.unit.util.RSAKeyGenerator;
import org.mule.modules.oidctokenvalidator.client.oidc.SignedTokenVerifier;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


public class SignedTokenVerifierTest {

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
		assertTrue(SignedTokenVerifier.isActive(System.currentTimeMillis() + 10000, System.currentTimeMillis() - 10000));
	}
	
	@Test
	public void isActiveShouldReturnFalse() throws Exception {
		assertFalse(SignedTokenVerifier.isActive(System.currentTimeMillis() - 10000, System.currentTimeMillis() + 10000));
	}
	
	@Test(expected=TokenValidationException.class)
	public void verifyTokenShouldThrowTokenValidationException() throws Exception{
		json.put("iss", props.getProperty("sso-url"));
		json.put("exp", 0);
		json.put("nbf", 0);
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), JWTClaimsSet.parse(json));
		jwt.sign(signer);
		SignedTokenVerifier.verifyToken(verifier, jwt, props.getProperty("sso-url"));
	}
	
	@Test
	public void verifyTokenShouldReturnClaimSet() throws Exception{
		json.put("iss", props.getProperty("sso-url"));
		json.put("exp", System.currentTimeMillis() + 10000);
		json.put("nbf", 0);
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS512), JWTClaimsSet.parse(json));
		jwt.sign(signer);
		assertTrue(SignedTokenVerifier.verifyToken(verifier, jwt, props.getProperty("sso-url")) instanceof JWTClaimsSet);
	}
}
