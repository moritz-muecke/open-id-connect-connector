package org.mule.modules.oidctokenvalidator.client.tokenvalidation;

import java.io.IOException;

import net.minidev.json.JSONObject;

import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.HTTPConnectException;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenValidator {

	private TokenVerifier verifier;

	private static final Logger logger = LoggerFactory.getLogger(TokenValidator.class);

	public TokenValidator(TokenVerifier verifier) {
		this.verifier = verifier;
	}

	public JSONObject introspectionTokenValidation(String authHeader, SingleSignOnConfig ssoConfig)
			throws TokenValidationException, HTTPConnectException {
		try {
			AccessToken accessToken = AccessToken.parse(authHeader);

			TokenIntrospectionRequest introspectionRequest = createTokenIntrospectionRequest(accessToken, ssoConfig);

			logger.debug("Sending token introspection HTTP request to identity provider");
			HTTPResponse introspectionHttpResponse = introspectionRequest
					.toHTTPRequest().send();

			// TODO: Ghetto Fix, because Keycloak does not set the content type in introspection response
			introspectionHttpResponse
					.setContentType(CommonContentTypes.APPLICATION_JSON);

			TokenIntrospectionResponse introspectionResponse = TokenIntrospectionResponse
					.parse(introspectionHttpResponse);

			if (introspectionResponse instanceof TokenIntrospectionErrorResponse) {
				logger.debug("Received an error response from introspection request");
				ErrorObject errorResponse = ((TokenIntrospectionErrorResponse) introspectionResponse)
						.getErrorObject();
				throw new TokenValidationException(
						errorResponse.getDescription());
			}

			TokenIntrospectionSuccessResponse successResponse =
					(TokenIntrospectionSuccessResponse) introspectionResponse;
			JSONObject claims = successResponse.toJSONObject();
			if (!(boolean)claims.get("active")) {
				logger.debug("Token validation with introspection failed. Token isn't active");
				throw new TokenValidationException("Token is not active");
			}
			return claims;
		} catch (IOException e) {
			logger.debug("Could not connect to identity provider for token introspection");
			throw new HTTPConnectException(
					String.format("Could not connect to the identity provider %s - Error: %s",
							ssoConfig.getSsoUri(), e.getMessage())
			);
		} catch (Exception e) {
			logger.debug("Error during token introspection. Exception: {}, Message: {}", e.getCause(), e.getMessage());
			throw new TokenValidationException(e.getMessage());
		}
	}

	public JWTClaimsSet localTokenValidation(String authHeader, SingleSignOnConfig ssoConfig)
			throws TokenValidationException {
		try {
			AccessToken accessToken = AccessToken.parse(authHeader);
			return verifier.verifyAccessToken(
					accessToken, ssoConfig.getRsaPublicKey(), ssoConfig.getSsoUri().toString()
			);
		} catch (Exception e) {
			logger.debug("Error during local token validation. Exception: {}, Message: {}",
					e.getCause(), e.getMessage());
			throw new TokenValidationException(e.getMessage());
		}
	}
	
	public TokenIntrospectionRequest createTokenIntrospectionRequest(
			AccessToken accessToken, SingleSignOnConfig ssoConfig) {
		return new TokenIntrospectionRequest(
				ssoConfig.getIntrospectionUri(),
				ssoConfig.getClientSecretBasic(),
				accessToken);
	}
}
