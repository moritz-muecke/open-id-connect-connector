package org.mule.modules.openidconnect.client.tokenvalidation;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.JWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
import org.mule.modules.openidconnect.client.NimbusParserUtil;
import org.mule.modules.openidconnect.config.SingleSignOnConfig;
import org.mule.modules.openidconnect.exception.TokenValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

/**
 * Provides methods to verify OpenID Connect Access-, Refresh- and ID-Tokens.
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class TokenVerifier {

	private static final Logger logger = LoggerFactory.getLogger(TokenVerifier.class);

	private NimbusParserUtil parser;

	public TokenVerifier() {
		this.parser = new NimbusParserUtil();
	}

    /**
     * Verifies that a given AccessToken is valid by comparing the issuer with the origin, checking if its active and
     * verifying the token signature with a given public key
     *
     * @param accessToken AccessToken which has to be verified
     * @param publicKey The public key to verify the signature of the token
     * @param origin The origin which provided the token
     * @return The claims set of the given token
     * @throws TokenValidationException if verifying fails
     */
	public JWTClaimsSet verifyAccessToken(AccessToken accessToken, RSAPublicKey publicKey, String origin) throws
			TokenValidationException {
		try {

			SignedJWT signedJWT = parser.parseSignedJWT(accessToken.getValue());
			JWSVerifier verifier = new RSASSAVerifier(publicKey);
            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();

            String issuer = claimSet.getIssuer();

			if (!signedJWT.verify(verifier)) throw new TokenValidationException("Wrong token signature");
			if (!issuer.equals(origin)) throw new TokenValidationException("Token has wrong issuer");
			if (!isActive(accessToken)) throw new TokenValidationException("Token isn't active");
			
			return claimSet;
		} catch (Exception e) {
			logger.debug("Error during access token verification. Exception: {}, Message: {}",
					e.getCause(), e.getMessage());
			throw new TokenValidationException(e.getMessage());
		}
	}

    /**
     * Verifies a given IDToken by using the token verifier from the Nimbus SDK. Also verifying the token signature
     * with the public key. Follows the defined guideline of the OpenID Connect specification
     *
     * @param idToken IDToken which has to be verified
     * @param ssoConfig Config object with all necessary identity provider information
     * @param nonce Nonce from the initial authentication redirect
     * @throws TokenValidationException if verifying fails
     */
	public void verifyIdToken(JWT idToken, SingleSignOnConfig ssoConfig, Nonce nonce) throws TokenValidationException {
		try {
			OIDCProviderMetadata metaData = ssoConfig.getProviderMetadata();
			JWTClaimsSet claimSet = idToken.getJWTClaimsSet();
			JWTClaimsVerifier verifier = new IDTokenClaimsVerifier(
					metaData.getIssuer(), ssoConfig.getClientSecretBasic().getClientID(), nonce, 0
			);
			verifier.verify(claimSet);

            if(ssoConfig.getRsaPublicKey() != null) {
                SignedJWT signedJWT = parser.parseSignedJWT(idToken.getParsedString());
                JWSVerifier jwsVerifier = new RSASSAVerifier(ssoConfig.getRsaPublicKey());
                if (!signedJWT.verify(jwsVerifier)){
                    throw new TokenValidationException("Wrong token signature");
                }
            } else throw new TokenValidationException("RSA public key is null");

		} catch (Exception e) {
			logger.debug("Error during id token verification. Exception: {}, Message: {}",
					e.getCause(), e.getMessage());
			throw new TokenValidationException(e.getMessage());
		}

	}

    /**
     * Compares a refreshed ID-Token with the current one. Follows the defined guideline of the OpenID Connect
     * specification
     *
     * @param currentIdToken Current ID-Token
     * @param newIdToken Refreshed ID-Token obtained from the identity provider
     * @throws TokenValidationException if verifying fails
     */
	public void verifyRefreshedIdToken(JWT currentIdToken, JWT newIdToken) throws TokenValidationException {
        try {
            JWTClaimsSet currentClaims = currentIdToken.getJWTClaimsSet();
            JWTClaimsSet newClaims = newIdToken.getJWTClaimsSet();
            if (!currentClaims.getIssuer().equals(newClaims.getIssuer())){
                throw new TokenValidationException("Refreshed ID token issuer doesn't match current issuer");
            }
            if (!currentClaims.getSubject().equals(newClaims.getSubject())){
                throw new TokenValidationException("Refreshed ID token subject doesn't match current subject");
            }
            if (newClaims.getIssueTime().getTime() > System.currentTimeMillis()){
                throw new TokenValidationException("Invalid issue time in refreshed ID token");
            }
            if (!currentClaims.getAudience().equals(newClaims.getAudience())){
                throw new TokenValidationException("Refreshed ID token audience doesn't match current audience");
            }
        } catch (Exception e) {
			logger.debug("Error during refresh token verification. Exception: {}, Message: {}",
					e.getCause(), e.getMessage());
            throw new TokenValidationException(e.getMessage());
        }
    }

    /**
     * Helper method to check if a given AccessToken is active
     *
     * @param accessToken AccessToken to be checked
     * @return True if active, false if not
     * @throws ParseException if token can't be parsed
     */
	public boolean isActive(AccessToken accessToken) throws ParseException {
        JWTClaimsSet claimsSet = parser.parseJWT(accessToken.getValue()).getJWTClaimsSet();
		long expTime = claimsSet.getExpirationTime().getTime();
		long notBeforeTime = claimsSet.getNotBeforeTime().getTime();
		return System.currentTimeMillis() < expTime && System.currentTimeMillis() >= notBeforeTime;
	}

	public void setParser(NimbusParserUtil parser) {
		this.parser = parser;
	}
}
