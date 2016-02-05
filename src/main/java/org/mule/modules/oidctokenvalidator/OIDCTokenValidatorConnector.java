package org.mule.modules.oidctokenvalidator;
import java.util.Map;

import javax.enterprise.inject.Default;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import org.mule.api.MuleMessage;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.lifecycle.Start;
import org.mule.api.annotations.param.InboundHeaders;
import org.mule.api.callback.SourceCallback;
import org.mule.api.transport.PropertyScope;
import org.mule.modules.oidctokenvalidator.client.OpenIDConnectClient;
import org.mule.modules.oidctokenvalidator.client.TokenValidatorClient;
import org.mule.modules.oidctokenvalidator.config.ConnectorConfig;
import org.mule.modules.oidctokenvalidator.exception.HTTPConnectException;
import org.mule.modules.oidctokenvalidator.exception.MetaDataInitializationException;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;
import org.mule.transport.http.components.HttpResponseBuilder;


@Connector(name="oidc-token-validator", friendlyName="OIDCTokenValidator")
public class OIDCTokenValidatorConnector {

	private TokenValidatorClient client;
	private final static String HTTP_STATUS = "http.status";
	private final static String HTTP_REASON = "http.reason";
	
	@Config
    ConnectorConfig config;
    
    @Start
    public void init() throws MetaDataInitializationException {
    	client = new OpenIDConnectClient(config);
    }
    
        
    /**
     * Uses OIDC token introspection to validate a bearer token
     * 
     * {@sample.xml ../../../doc/oidc-token-validator-connector.xml.sample
	 * oidc-token-validator:online-token-validation}
     * 
     * @param callback injected by devkit
     * @param muleMessage injected by devkit
     * @param headers Authorization header where the bearer token is located
     * @param introspectionEndpoint The path of the introspection endpoint
     * @param clientID Any Client-ID from the SSO to prevent token scanning attacks
     * @param clientSecret The Secret of the given Client-ID
     * @param claimExtraction Creates the FlowVar tokenClaims which contains a map with all claims of the given token
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     * @throws HTTPConnectException if the identity provider is not available
     */
    @Processor(intercepting = true)
    public Object onlineTokenValidation(
    		SourceCallback callback, 
    		MuleMessage muleMessage, 
    		@InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers, 
    		String introspectionEndpoint, 
    		@FriendlyName("Client ID")String clientID, 
    		String clientSecret,
    		boolean claimExtraction) throws HTTPConnectException {
    	config.setClientId(clientID);
    	config.setClientSecret(clientSecret);
    	config.setIntrospectionEndpoint(introspectionEndpoint);
    	try {
    		Map<String, Object> claims = client.ssoTokenValidation(headers.get(HttpHeaders.AUTHORIZATION));
			if (claimExtraction) {
				muleMessage.setInvocationProperty("tokenClaims", claims);
			}
			return callback.process(muleMessage);
		} catch (TokenValidationException e) {
			muleMessage.setOutboundProperty(HTTP_STATUS, Response.Status.UNAUTHORIZED.getStatusCode());
			muleMessage.setOutboundProperty(HTTP_REASON, Response.Status.UNAUTHORIZED.getReasonPhrase());
			muleMessage.setPayload(e.getMessage());
			return muleMessage.getPayload();
		} catch (HTTPConnectException e) {
			muleMessage.setOutboundProperty(HTTP_STATUS, Response.Status.SERVICE_UNAVAILABLE.getStatusCode());
			muleMessage.setOutboundProperty(HTTP_REASON, Response.Status.SERVICE_UNAVAILABLE.getReasonPhrase());
			muleMessage.setPayload(e.getMessage());
			throw e;
		} catch (Exception e) {
			muleMessage.setOutboundProperty(HTTP_STATUS, Response.Status.BAD_REQUEST.getStatusCode());
			muleMessage.setOutboundProperty(HTTP_REASON, Response.Status.BAD_REQUEST.getReasonPhrase());
			muleMessage.setPayload(e.getMessage());	
			return muleMessage.getPayload();
		}
    }
    
    
    /**
     * Local validation of a bearer token
     * 
     * {@sample.xml ../../../doc/oidc-token-validator-connector.xml.sample
	 * oidc-token-validator:local-token-validation}
     * 
     * @param callback injected by devkit
     * @param muleMessage injected by devkit
     * @param headers Authorization header where the bearer token is located
     * @param claimExtraction Creates the FlowVar tokenClaims which contains a map with all claims of the given token
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @Processor(intercepting = true)
    public Object localTokenValidation(
    		SourceCallback callback, 
    		MuleMessage muleMessage, 
    		@InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers, 
    		boolean claimExtraction) {
    	try {
			Map<String, Object> claims = client.localTokenValidation(headers.get(HttpHeaders.AUTHORIZATION));
			if (claimExtraction) {
				muleMessage.setInvocationProperty("tokenClaims", claims);
				muleMessage.setProperty("tokenClaims", claims, PropertyScope.INBOUND);
			}
			return callback.process(muleMessage, claims);
		} catch (TokenValidationException e) {
			muleMessage.setOutboundProperty(HTTP_STATUS, Response.Status.UNAUTHORIZED.getStatusCode());
			muleMessage.setOutboundProperty(HTTP_REASON, Response.Status.UNAUTHORIZED.getReasonPhrase());
			muleMessage.setPayload(e.getMessage());	
			return muleMessage.getPayload();
		} catch (Exception e) {
			muleMessage.setOutboundProperty(HTTP_STATUS, Response.Status.BAD_REQUEST.getStatusCode());
			muleMessage.setOutboundProperty(HTTP_REASON, Response.Status.BAD_REQUEST.getReasonPhrase());
			muleMessage.setPayload(e.getMessage());	
			return muleMessage.getPayload();
		}
    }
    
    /**
     * Connector works as a OIDC relying party
     * 
     * {@sample.xml ../../../doc/oidc-token-validator-connector.xml.sample
	 * oidc-token-validator:act-as-relying-party}
     * 
     * @param callback injected by devkit
     * @param muleMessage injected by devkit
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     * @throws Exception 
     */
    @Processor(intercepting = true)
    public Object actAsRelyingParty(SourceCallback callback, MuleMessage muleMessage) throws Exception {
    	Map<String, String> queryParams = muleMessage.getInboundProperty("http.query.params");
    	if(queryParams.get("code") != null){
			return callback.process();
		} else {
			muleMessage.setOutboundProperty(HTTP_STATUS, Response.Status.FOUND.getStatusCode());
			muleMessage.setOutboundProperty(HTTP_REASON, Response.Status.FOUND.getReasonPhrase());
	        muleMessage.setOutboundProperty("Location", "http://localhost:8080/auth/realms/master/protocol/openid-connect/auth?response_type=code&scope=openid&client_id=account&redirect_uri=http://localhost:8081");
	        return muleMessage.getPayload();	
		}
    }
    
    public ConnectorConfig getConfig() {
        return config;
    }

    public void setConfig(ConnectorConfig config) {
        this.config = config;
    }
    
    public TokenValidatorClient getClient() {
		return client;
	}

	public void setClient(TokenValidatorClient client) {
		this.client = client;
	}

}