package org.mule.modules.singlesignonoidc.client;

import java.io.IOException;
import java.security.PublicKey;

import net.minidev.json.JSONObject;

import org.apache.logging.log4j.status.StatusLogger;
import org.keycloak.RSATokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.PemUtils;
import org.mule.modules.singlesignonoidc.config.ConnectorConfig;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;

public class TokenValidator {
	
	private static final StatusLogger logger = StatusLogger.getLogger();
	
	private ConnectorConfig connectorConfig;
	private PublicKey publicKey;
	
	public TokenValidator(ConnectorConfig config) {
		connectorConfig = config;
		try {
			publicKey = config.getRsaPublicKey();
		} catch (Exception e) {
			logger.error("PublicKey could not decode public key: " + e.getMessage());
		}
	}

	public void introspectionTokenValidation(String authHeader) throws ParseException, IOException {
		AccessToken token = AccessToken.parse(authHeader);
		TokenIntrospectionRequest introspectionRequest = new TokenIntrospectionRequest(connectorConfig.getIntrospectionUri(), token);
		HTTPResponse introSpectionHttpResponse = null;
		introSpectionHttpResponse = introspectionRequest.toHTTPRequest().send();
		TokenIntrospectionResponse introspectionResponse = null;
		introspectionResponse = TokenIntrospectionResponse.parse(introSpectionHttpResponse);
		
		if(introspectionResponse instanceof TokenIntrospectionErrorResponse) {
			ErrorObject errorResponse = ((TokenIntrospectionErrorResponse) introspectionResponse).getErrorObject();
			logger.error("Status:" + errorResponse.getHTTPStatusCode() + "Error: " + errorResponse.getDescription());
		}
		
		TokenIntrospectionSuccessResponse successResponse = (TokenIntrospectionSuccessResponse) introspectionResponse;
		JSONObject claims = successResponse.toJSONObject();
		logger.info(claims);
	}

	public void localTokenValidation(String accessToken) throws VerificationException {
		RSATokenVerifier.verifyToken(accessToken, publicKey, connectorConfig.getProviderMetadata().getIssuer().toString(), true, true);
	}
}
