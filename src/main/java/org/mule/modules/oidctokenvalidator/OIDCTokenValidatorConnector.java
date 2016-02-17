package org.mule.modules.oidctokenvalidator;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import org.apache.commons.httpclient.Cookie;
import org.mule.api.MuleContext;
import org.mule.api.MuleEvent;
import org.mule.api.MuleMessage;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.lifecycle.Start;
import org.mule.api.annotations.param.InboundHeaders;
import org.mule.api.annotations.param.OutboundHeaders;
import org.mule.api.callback.SourceCallback;
import org.mule.api.store.ObjectStore;
import org.mule.api.store.ObjectStoreException;
import org.mule.api.transport.PropertyScope;
import org.mule.modules.oidctokenvalidator.client.OpenIdConnectClientImpl;
import org.mule.modules.oidctokenvalidator.client.OpenIdConnectClient;
import org.mule.modules.oidctokenvalidator.client.oidc.*;
import org.mule.modules.oidctokenvalidator.config.ConnectorConfig;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.HTTPConnectException;
import org.mule.modules.oidctokenvalidator.exception.MetaDataInitializationException;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;
import org.mule.transport.http.CookieHelper;


@Connector(name="oidc-token-validator", friendlyName="OIDCTokenValidator")
public class OIDCTokenValidatorConnector {

	private OpenIdConnectClient client;
	private final static String HTTP_STATUS = "http.status";
	private final static String HTTP_REASON = "http.reason";

	@Config
    ConnectorConfig config;


    @Start
    public void init() throws MetaDataInitializationException {
        SingleSignOnConfig ssoConfig = new SingleSignOnConfig(config);
        TokenStorage storage = new TokenStorageImpl();
        TokenRequester requester = new TokenRequesterImpl();
        TokenValidator validator = new TokenValidator(ssoConfig);
    	client = new OpenIdConnectClientImpl(config, ssoConfig, validator, requester, storage);
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
     * @param muleEvent injected by devkit
     * @param headers Authorization header where the bearer token is located
     * @param claimExtraction Creates the FlowVar tokenClaims which contains a map with all claims of the given token
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @Processor(intercepting = true)
    public Object localTokenValidation(
    		SourceCallback callback, 
    		MuleEvent muleEvent,
    		@InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers, 
    		boolean claimExtraction) {

		MuleMessage muleMessage = muleEvent.getMessage();

    	try {
			Map<String, Object> claims = client.localTokenValidation(headers.get(HttpHeaders.AUTHORIZATION));
			if (claimExtraction) {
                muleMessage.setInvocationProperty("tokenClaims", claims);
				muleMessage.addProperties(claims, PropertyScope.OUTBOUND);
            }
			return callback.processEvent(muleEvent);
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
    	muleMessage = client.actAsRelyingParty(muleMessage);

		Map<String, String> queryParams = muleMessage.getInboundProperty("http.query.params");
        System.out.println(queryParams);
        if(queryParams.get("code") != null){
			return callback.process();
		} else {
			muleMessage.setOutboundProperty(HTTP_STATUS, Response.Status.FOUND.getStatusCode());
			muleMessage.setOutboundProperty(HTTP_REASON, Response.Status.FOUND.getReasonPhrase());
	        muleMessage.setOutboundProperty("Location", "http://localhost:8080/auth/realms/master/protocol/openid-connect/auth?response_type=code&scope=openid&client_id=account&redirect_uri=http://localhost:8081");
	        return muleMessage.getPayload();	
		}
    }


	/*
	@Processor
	public void cookieTest(@OutboundHeaders Map<String, Object> headers, MuleMessage muleMessage) {


		String cookieHeader = muleMessage.getInboundProperty("cookie");

        String[] cookies = cookieHeader.split(";");



        Cookie cookie = new Cookie("localhost:8080", COOKIE_NAME, "123.avc.asd");
		headers.put(org.mule.module.http.api.HttpHeaders.Names.SET_COOKIE, cookie);
    }
    */

    @Processor
    public void objectStoreTest(MuleContext context, String key) throws ObjectStoreException {
        ObjectStore<String> store = context.getObjectStoreManager().getObjectStore("oidc-connector");
        store.store(key, UUID.randomUUID().toString());
        store.retrieve("moritz");
    }


    public ConnectorConfig getConfig() {
        return config;
    }

    public void setConfig(ConnectorConfig config) {
        this.config = config;
    }
    
    public OpenIdConnectClient getClient() {
		return client;
	}

	public void setClient(OpenIdConnectClient client) {
		this.client = client;
	}

}