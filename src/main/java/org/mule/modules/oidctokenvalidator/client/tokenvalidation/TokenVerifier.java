package org.mule.modules.oidctokenvalidator.client.tokenvalidation;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.JWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class TokenVerifier {

	private static final Logger logger = LoggerFactory.getLogger(TokenVerifier.class);


	public JWTClaimsSet verifyAccessToken(AccessToken accessToken, RSAPublicKey publicKey, String origin) throws
			TokenValidationException {
		try {
			SignedJWT signedJWT = SignedJWT.parse(accessToken.getValue());
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

	public void verifyIdToken(JWT idToken, SingleSignOnConfig ssoConfig, Nonce nonce) throws TokenValidationException {
		try {
			OIDCProviderMetadata metaData = ssoConfig.getProviderMetadata();
			JWTClaimsSet claimSet = idToken.getJWTClaimsSet();
			JWTClaimsVerifier verifier = new IDTokenClaimsVerifier(
					metaData.getIssuer(), ssoConfig.getClientSecretBasic().getClientID(), nonce, 0
			);
			verifier.verify(claimSet);

            if(ssoConfig.getRsaPublicKey() != null) {
                SignedJWT signedJWT = SignedJWT.parse(idToken.getParsedString());
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

	public boolean isActive(AccessToken accessToken) throws ParseException {
        JWTClaimsSet claimsSet = JWTParser.parse(accessToken.getValue()).getJWTClaimsSet();
		long expTime = claimsSet.getExpirationTime().getTime();
		long notBeforeTime = claimsSet.getNotBeforeTime().getTime();
		return System.currentTimeMillis() < expTime && System.currentTimeMillis() >= notBeforeTime;
	}

}
