package org.mule.modules.singlesignonoidc.client;

import net.minidev.json.JSONObject;

import org.mule.modules.singlesignonoidc.config.MetaDataProvider;
import org.mule.modules.singlesignonoidc.exception.TokenValidationException;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;

public class TokenValidator {

	private MetaDataProvider metaDataConfig;

	public TokenValidator(MetaDataProvider config) {
		metaDataConfig = config;
	}

	public void introspectionTokenValidation(String authHeader)
			throws TokenValidationException {
		try {
			AccessToken accessToken = AccessToken.parse(authHeader);

			TokenIntrospectionRequest introspectionRequest = new TokenIntrospectionRequest(
					metaDataConfig.getIntrospectionUri(),
					metaDataConfig.getClientSecretBasic(), accessToken);
			HTTPResponse introSpectionHttpResponse = introspectionRequest
					.toHTTPRequest().send();

			// TODO: Ghetto Fix, because of Keycloak Bug
			introSpectionHttpResponse
					.setContentType(CommonContentTypes.APPLICATION_JSON);

			TokenIntrospectionResponse introspectionResponse = TokenIntrospectionResponse
					.parse(introSpectionHttpResponse);

			if (introspectionResponse instanceof TokenIntrospectionErrorResponse) {
				ErrorObject errorResponse = ((TokenIntrospectionErrorResponse) introspectionResponse)
						.getErrorObject();
				throw new TokenValidationException(
						errorResponse.getDescription());
			}

			TokenIntrospectionSuccessResponse successResponse = (TokenIntrospectionSuccessResponse) introspectionResponse;
			JSONObject claims = successResponse.toJSONObject();
			if (!(boolean)claims.get("active")) {
				throw new TokenValidationException("Token is not active");
			}
		} catch (Exception e) {
			throw new TokenValidationException(e.getMessage());
		}
	}

	public JWTClaimsSet localTokenValidation(String authHeader)
			throws TokenValidationException {
		try {
			AccessToken accessToken = AccessToken.parse(authHeader);
			SignedJWT jwt = SignedJWT.parse(accessToken.getValue());
			JWSVerifier verifier = new RSASSAVerifier(
					metaDataConfig.getRsaPublicKey());
			return SignedTokenVerifier.verifyToken(verifier, jwt, metaDataConfig.getSsoUri().toString());
		} catch (Exception e) {
			throw new TokenValidationException(e.getMessage());
		}
	}
}
