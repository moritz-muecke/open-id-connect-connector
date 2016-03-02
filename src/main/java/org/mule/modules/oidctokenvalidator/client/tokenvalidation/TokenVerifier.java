package org.mule.modules.oidctokenvalidator.client.tokenvalidation;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.proc.JWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public abstract class TokenVerifier {
	public static JWTClaimsSet verifyAccessToken(AccessToken accessToken, RSAPublicKey publicKey, String origin) throws TokenValidationException {
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
			throw new TokenValidationException(e.getMessage());
		}
	}

	public static void verifyIdToken(JWT idToken, SingleSignOnConfig ssoConfig, Nonce nonce) throws TokenValidationException {
		try {
			OIDCProviderMetadata metaData = ssoConfig.getProviderMetadata();
			JWTClaimsSet claimSet = idToken.getJWTClaimsSet();
			JWTClaimsVerifier verifier = new IDTokenClaimsVerifier(metaData.getIssuer(), ssoConfig.getClientSecretBasic().getClientID(), nonce, 0);
			verifier.verify(claimSet);

            if(ssoConfig.getRsaPublicKey() != null) {
                SignedJWT signedJWT = SignedJWT.parse(idToken.getParsedString());
                JWSVerifier jwsVerifier = new RSASSAVerifier(ssoConfig.getRsaPublicKey());
                if (!signedJWT.verify(jwsVerifier)){
                    throw new TokenValidationException("Wrong token signature");
                }
            }

		} catch (Exception e) {
			System.out.println(e.getCause() + " : " + e.getMessage());
			throw new TokenValidationException(e.getMessage());
		}

	}

	public static boolean isActive(AccessToken accessToken) throws ParseException {
		JWTClaimsSet claimsSet = SignedJWT.parse(accessToken.getValue()).getJWTClaimsSet();
		long expTime = claimsSet.getExpirationTime().getTime();
		long notBeforeTime = claimsSet.getNotBeforeTime().getTime();
		return System.currentTimeMillis() < expTime && System.currentTimeMillis() >= notBeforeTime;
	}
}
