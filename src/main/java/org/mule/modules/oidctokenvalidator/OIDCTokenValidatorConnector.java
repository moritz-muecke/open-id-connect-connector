package org.mule.modules.oidctokenvalidator;
import java.io.Serializable;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.inject.Inject;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.apache.commons.httpclient.Cookie;
import org.mule.api.MuleContext;
import org.mule.api.MuleEvent;
import org.mule.api.MuleException;
import org.mule.api.MuleMessage;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.display.Password;
import org.mule.api.annotations.lifecycle.Start;
import org.mule.api.annotations.param.InboundHeaders;
import org.mule.api.annotations.param.OutboundHeaders;
import org.mule.api.callback.SourceCallback;
import org.mule.api.store.ListableObjectStore;
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

    @Inject
    MuleContext muleContext;

    @Start
    public void init() throws MetaDataInitializationException, ObjectStoreException {
        SingleSignOnConfig ssoConfig = new SingleSignOnConfig(config);
        ListableObjectStore<String> tokenStore = muleContext.getObjectStoreManager().getObjectStore("oidc-connector");
        TokenStorage storage = new TokenStorageImpl(tokenStore);
        TokenRequester requester = new TokenRequesterImpl(ssoConfig);
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
     * @param muleEvent injected by devkit
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
    		MuleEvent muleEvent,
    		@InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers, 
    		String introspectionEndpoint, 
    		@FriendlyName("Client ID")String clientID, 
    		String clientSecret,
    		boolean claimExtraction) throws HTTPConnectException {

		MuleMessage muleMessage = muleEvent.getMessage();
		config.setClientId(clientID);
    	config.setClientSecret(clientSecret);
    	config.setIntrospectionEndpoint(introspectionEndpoint);
    	try {
    		Map<String, Object> claims = client.ssoTokenValidation(headers.get(HttpHeaders.AUTHORIZATION));
			if (claimExtraction) {
				muleMessage.setInvocationProperty("tokenClaims", claims);
			}
            return callback.processEvent(muleEvent).getMessage().getPayload();
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
            }
			return callback.processEvent(muleEvent).getMessage().getPayload();
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
     * @param muleEvent injected by devkit
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     * @throws Exception 
     */
    @Processor(intercepting = true)
    public Object actAsRelyingParty(SourceCallback callback, MuleEvent muleEvent, String redirectUri, String clientId, @Password String clientSecret) throws Exception {

        MuleMessage muleMessage = muleEvent.getMessage();

        ClientSecretBasic clientSecretBasic = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
        client.getSsoConfig().setRedirectUri(new URI(redirectUri));
        client.getSsoConfig().setClientSecretBasic(clientSecretBasic);

        if (client.actAsRelyingParty(muleMessage)) {
            return callback.process(muleMessage);
        } else return muleMessage.getPayload();
    }

	@Processor(intercepting = true)
	public Object eventCallbackTest(SourceCallback callback, MuleEvent muleEvent) throws MuleException {
		muleEvent.getMessage().setInvocationProperty("Hallo", "Welt");
		return callback.processEvent(muleEvent).getMessage();
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

    public MuleContext getMuleContext() {
        return muleContext;
    }

    public void setMuleContext(MuleContext muleContext) {
        this.muleContext = muleContext;
    }
}