package org.mule.modules.singlesignonoidc.client;

import java.io.IOException;
import java.util.Map;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.keycloak.common.VerificationException;
import org.mule.modules.singlesignonoidc.SingleSignOnOIDCConnector;
import org.mule.modules.singlesignonoidc.config.ConnectorConfig;
import org.mule.modules.singlesignonoidc.exception.HeaderFormatException;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator;

public class OpenIDConnectClient {
	
	private TokenValidator tokenValidator;
	private ConnectorConfig config;	
	private static final String BEARER_PREFIX = "Bearer ";
	
	public OpenIDConnectClient(ConnectorConfig config) {
		this.config = config;
		this.tokenValidator = new TokenValidator(this.config);
	}
	
	public void validateToken(String authHeader, boolean online) 
			throws HeaderFormatException, VerificationException, ParseException, IOException {
		String accessToken = extractTokenString(authHeader);
		if (online) {
			tokenValidator.introspectionTokenValidation(authHeader);
		} else {
			tokenValidator.localTokenValidation(accessToken);
		}
	}
	
	private String extractTokenString(String authHeader) 
			throws HeaderFormatException {
		if (authHeader.length() <= BEARER_PREFIX.length() || !authHeader.startsWith(BEARER_PREFIX)) {
			throw new HeaderFormatException("Authorization header has wrong format");
		}
		return authHeader.substring(BEARER_PREFIX.length());
	}
}

