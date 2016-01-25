package org.mule.modules.singlesignonoidc.client;

import java.io.IOException;
import java.security.PublicKey;

import net.minidev.json.JSONObject;

import org.apache.logging.log4j.status.StatusLogger;
import org.keycloak.RSATokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.PemUtils;
import org.mule.modules.singlesignonoidc.config.ConnectorConfig;
import org.mule.modules.singlesignonoidc.exception.TokenIntrospectionException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;

public class TokenValidator {
		
	private ConnectorConfig connectorConfig;
	
	public TokenValidator(ConnectorConfig config) {
		connectorConfig = config;
	}

	public void introspectionTokenValidation(AccessToken accessToken) throws ParseException, IOException, TokenIntrospectionException {
		TokenIntrospectionRequest introspectionRequest = new TokenIntrospectionRequest(connectorConfig.getIntrospectionUri(), connectorConfig.getClientSecretBasic(), accessToken);
		HTTPResponse introSpectionHttpResponse = introspectionRequest.toHTTPRequest().send();
		
		// TODO: Ghetto Fix, because of Keycloak Bug
		introSpectionHttpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		
		TokenIntrospectionResponse introspectionResponse = TokenIntrospectionResponse.parse(introSpectionHttpResponse);
		
		if(introspectionResponse instanceof TokenIntrospectionErrorResponse) {
			ErrorObject errorResponse = ((TokenIntrospectionErrorResponse) introspectionResponse).getErrorObject();
			throw new TokenIntrospectionException(errorResponse.getDescription());
		}
		
		TokenIntrospectionSuccessResponse successResponse = (TokenIntrospectionSuccessResponse) introspectionResponse;
		JSONObject claims = successResponse.toJSONObject();
		boolean active = (boolean) claims.get("active");
		if(!active) {
			throw new TokenIntrospectionException("Token is not active");
		}
	}

	public void localTokenValidation(AccessToken accessToken) throws VerificationException, java.text.ParseException, JOSEException {
		SignedJWT jwt = SignedJWT.parse(accessToken.getValue());
		JWSVerifier verifier = new RSASSAVerifier(connectorConfig.getRsaPublicKey());
		boolean verification = jwt.verify(verifier);
	}
}
