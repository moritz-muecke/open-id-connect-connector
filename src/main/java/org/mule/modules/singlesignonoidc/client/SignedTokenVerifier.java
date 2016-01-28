package org.mule.modules.singlesignonoidc.client;
import org.mule.modules.singlesignonoidc.exception.TokenValidationException;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class SignedTokenVerifier {
	public static JWTClaimsSet verifyToken(JWSVerifier verifier, SignedJWT signedJWT, String origin) throws TokenValidationException {
		try {
			JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();
			
			String issuer = claimSet.getIssuer();
			long expTime = claimSet.getExpirationTime().getTime();
			long notBeforeTime = claimSet.getNotBeforeTime().getTime();
			
			if (!signedJWT.verify(verifier)) throw new TokenValidationException("Wrong token signature");
			if (!issuer.equals(origin)) throw new TokenValidationException("Token has wrong issuer");
			if (!isActive(expTime, notBeforeTime)) throw new TokenValidationException("Token isn't active");
			
			return claimSet;
		} catch (Exception e) {
			throw new TokenValidationException(e.getMessage());
		}
	}
	
	public static boolean isActive(long expTime, long notBeforeTime) {
		return System.currentTimeMillis() < expTime && System.currentTimeMillis() >= notBeforeTime;
	}
}
