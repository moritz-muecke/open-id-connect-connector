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
import org.mule.modules.singlesignonoidc.exception.TokenValidationException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator;

public class OpenIDConnectClient {
	
	private TokenValidator tokenValidator;
	private ConnectorConfig config;	
	
	public OpenIDConnectClient(ConnectorConfig config) {
		this.config = config;
		this.tokenValidator = new TokenValidator(this.config);
	}
	
	public void validateToken(String authHeader, boolean online) throws TokenValidationException {
		if (online) {
			tokenValidator.introspectionTokenValidation(authHeader);
		} else {
			tokenValidator.localTokenValidation(authHeader);
		}
	}
}

