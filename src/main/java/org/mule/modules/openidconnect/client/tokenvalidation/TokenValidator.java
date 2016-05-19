package org.mule.modules.openidconnect.client.tokenvalidation;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import net.minidev.json.JSONObject;
import org.mule.modules.openidconnect.client.NimbusParserUtil;
import org.mule.modules.openidconnect.config.SingleSignOnConfig;
import org.mule.modules.openidconnect.exception.HTTPConnectException;
import org.mule.modules.openidconnect.exception.TokenValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * This class provides the functionality to validate tokens. Local with the TokenVerifier or with sending a http
 * request to the identity provider for token introspection
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class TokenValidator {

	private TokenVerifier verifier;
	private NimbusParserUtil parser;

	private static final Logger logger = LoggerFactory.getLogger(TokenValidator.class);

	public TokenValidator(TokenVerifier verifier) {
		this.verifier = verifier;
        this.parser = new NimbusParserUtil();
	}

    /**
     * Validates a token from authHeader by sending an http request to the introspection endpoint of an identity
     * provider
     *
     * @param authHeader Authorization header string from HTTP Request
     * @param ssoConfig Config object with all necessary identity provider information
     * @return JSONObject including the token claims
     * @throws TokenValidationException if introspection fails
     * @throws HTTPConnectException if connecting to the identity provider fails
     */
	public JSONObject introspectionTokenValidation(String authHeader, SingleSignOnConfig ssoConfig)
			throws TokenValidationException, HTTPConnectException {
		try {
			AccessToken accessToken = parser.parseAccessToken(authHeader);

			TokenIntrospectionRequest introspectionRequest = createTokenIntrospectionRequest(accessToken, ssoConfig);
			logger.debug("Sending token introspection HTTP request to identity provider");
			HTTPResponse httpResponse = introspectionRequest.toHTTPRequest().send();

            // ******** Workaround because Keycloak SSO does not set the content type in introspection response yet
            httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
            // ********

            TokenIntrospectionResponse introspectionResponse = parser.parseIntrospectionResponse(httpResponse);

			if (introspectionResponse instanceof TokenIntrospectionErrorResponse) {
				logger.debug("Received an error response from introspection request");
				ErrorObject errorResponse = ((TokenIntrospectionErrorResponse) introspectionResponse)
						.getErrorObject();
				throw new TokenValidationException(errorResponse.getDescription());
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
			throw new HTTPConnectException(String.format("Could not connect to the identity provider %s - Error: %s",
                            ssoConfig.getSsoUri(), e.getMessage())
			);
		} catch (Exception e) {
			logger.debug("Error during token introspection. Message: {}", e.getMessage());
            throw new TokenValidationException(e.getMessage());
		}
	}

    /**
     * Calls the TokenVerifier to verify the given token
     *
     * @param authHeader Authorization header string from HTTP Request
     * @param ssoConfig Config object with all necessary identity provider information
     * @return The JWTClaimsSet of the given token
     * @throws TokenValidationException if token validation fails
     */
	public JWTClaimsSet localTokenValidation(String authHeader, SingleSignOnConfig ssoConfig)
			throws TokenValidationException {
		try {
			AccessToken accessToken = parser.parseAccessToken(authHeader);
			return verifier.verifyAccessToken(
					accessToken, ssoConfig.getRsaPublicKey(), ssoConfig.getSsoUri().toString()
			);
		} catch (Exception e) {
			logger.debug("Error during local token validation. Message: {}", e.getMessage());
			throw new TokenValidationException(e.getMessage());
		}
	}

    /**
     * Builds and returns a valid token introspection request defined by RFC7662
     *
     * @param accessToken Token which has to be introspected
     * @param ssoConfig Config object with all necessary identity provider information
     * @return The introspection request
     * @see <a href="https://tools.ietf.org/html/rfc7662">RFC7662</a>
     */
	public TokenIntrospectionRequest createTokenIntrospectionRequest(
			AccessToken accessToken, SingleSignOnConfig ssoConfig) {
		return new TokenIntrospectionRequest(
				ssoConfig.getIntrospectionUri(),
				ssoConfig.getClientSecretBasic(),
				accessToken);
	}

    public void setParser(NimbusParserUtil parser) {
        this.parser = parser;
    }
}
