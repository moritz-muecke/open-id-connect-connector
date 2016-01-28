package org.mule.modules.singlesignonoidc;
import java.util.Map;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import org.mule.api.MuleMessage;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.annotations.lifecycle.Start;
import org.mule.api.annotations.param.InboundHeaders;
import org.mule.api.callback.SourceCallback;
import org.mule.modules.singlesignonoidc.client.OpenIDConnectClient;
import org.mule.modules.singlesignonoidc.config.ConnectorConfig;
import org.mule.modules.singlesignonoidc.exception.MetaDataInitializationException;
import org.mule.modules.singlesignonoidc.exception.TokenValidationException;
import org.mule.transport.http.components.HttpResponseBuilder;


@Connector(name="oidc-token-validator", friendlyName="OIDCTokenValidator")
public class SingleSignOnOIDCConnector {

	private OpenIDConnectClient client;
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
     * {@sample.xml ../../../doc/single-sign-on-oidc-connector.xml.sample
	 * oidc-token-validator:online-token-validation}
     * 
     * @param callback injected by devkit
     * @param muleMessage injected by devkit
     * @param headers Authorization header where the bearer token is located
     * @param introspectionEndpoint The path of the introspection endpoint
     * @param clientID Any Client-ID from the SSO to prevent token scanning attacks
     * @param clientSecret The Secret of the given Client-ID
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @Processor(intercepting = true)
    public Object onlineTokenValidation(SourceCallback callback, MuleMessage muleMessage, @InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers, String introspectionEndpoint, String clientID, String clientSecret) {
    	try {
			client.tokenIntrospection(headers.get(HttpHeaders.AUTHORIZATION), clientID, clientSecret, introspectionEndpoint);
			return callback.process(muleMessage.getPayload());
		} catch (TokenValidationException e) {
			muleMessage.setOutboundProperty(HTTP_STATUS, Response.Status.UNAUTHORIZED.getStatusCode());
			muleMessage.setOutboundProperty(HTTP_REASON, Response.Status.UNAUTHORIZED.getReasonPhrase());
			muleMessage.setPayload(e.getMessage());
			return muleMessage.getPayload();
		} catch (MetaDataInitializationException e) {
			muleMessage.setOutboundProperty(HTTP_STATUS, Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
			muleMessage.setOutboundProperty(HTTP_REASON, Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase());
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
     * Local validation of a bearer token
     * 
     * {@sample.xml ../../../doc/single-sign-on-oidc-connector.xml.sample
	 * oidc-token-validator:local-token-validation}
     * 
     * @param callback injected by devkit
     * @param muleMessage injected by devkit
     * @param headers Authorization header where the bearer token is located
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @Processor(intercepting = true)
    public Object localTokenValidation(SourceCallback callback, MuleMessage muleMessage, @InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers) {
    	try {
			client.localTokenValidation(headers.get(HttpHeaders.AUTHORIZATION));
			return callback.process(muleMessage.getPayload());
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
     * {@sample.xml ../../../doc/single-sign-on-oidc-connector.xml.sample
	 * oidc-token-validator:act-as-relying-party}
     * 
     * @param callback injected by devkit
     * @param muleMessage injected by devkit
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @Processor
    public void actAsRelyingParty() {
		System.out.println("Test");
    }
    
    public ConnectorConfig getConfig() {
        return config;
    }

    public void setConfig(ConnectorConfig config) {
        this.config = config;
    }
    
    public OpenIDConnectClient getClient() {
		return client;
	}

	public void setClient(OpenIDConnectClient client) {
		this.client = client;
	}

}