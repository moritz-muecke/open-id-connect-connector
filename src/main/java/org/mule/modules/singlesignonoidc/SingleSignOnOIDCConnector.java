package org.mule.modules.singlesignonoidc;

import java.util.Map;

import javax.ws.rs.core.HttpHeaders;

import org.keycloak.common.VerificationException;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.callback.SourceCallback;
import org.mule.api.MuleMessage;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.lifecycle.Start;
import org.mule.api.annotations.param.InboundHeaders;
import org.mule.modules.singlesignonoidc.client.OpenIDConnectClient;
import org.mule.modules.singlesignonoidc.config.ConnectorConfig;
import org.mule.modules.singlesignonoidc.exception.HeaderFormatException;
import org.mule.modules.singlesignonoidc.exception.TokenIntrospectionException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;

@Connector(name="oidc-token-validator", friendlyName="OIDCTokenValidator")
public class SingleSignOnOIDCConnector {

	private OpenIDConnectClient client;
	
	@Config
    ConnectorConfig config;
    
    @Start
    public void init() throws ParseException, JOSEException, java.text.ParseException {
    	client = new OpenIDConnectClient(config);
    	config.buildSsoUri();
		config.buildProviderMetadata();
    }
    
        
    /**
     * Uses OIDC token introspection to validate a bearer token
     * 
     * {@sample.xml ../../../doc/single-sign-on-oidc-connector.xml.sample
	 * oidc-token-validator:online-token-validation}
     * 
     * @param callback
     * @param muleMessage
     * @param headers Authorization header where the bearer token is located
     * @param introspectionEndpoint The path of the introspection endpoint
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @Processor(intercepting = true)
    public Object onlineTokenValidation(SourceCallback callback, MuleMessage muleMessage, @InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers, String introspectionEndpoint) {
    	config.buildIntrospectionUri(introspectionEndpoint);
    	try {
			client.validateToken(headers.get(HttpHeaders.AUTHORIZATION), true);
			return callback.process(muleMessage.getPayload());
		} catch (TokenIntrospectionException e) {
			muleMessage.setOutboundProperty("http.status", 401);
			muleMessage.setPayload(e.getMessage());
			return muleMessage.getPayload();
		} catch (Exception e) {
			muleMessage.setOutboundProperty("http.status", 400);
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
     * @param callback
     * @param muleMessage
     * @param headers Authorization header where the bearer token is located
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @Processor(intercepting = true)
    public Object localTokenValidation(SourceCallback callback, MuleMessage muleMessage, @InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers) {
    	try {
			client.validateToken(headers.get(HttpHeaders.AUTHORIZATION), false);
			return callback.process(muleMessage.getPayload());
		} catch (VerificationException e) {
			muleMessage.setOutboundProperty("http.status", 401);
			muleMessage.setPayload(e.getMessage());	
			return muleMessage.getPayload();
		} catch (Exception e) {
			muleMessage.setOutboundProperty("http.status", 500);
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
     * @param callback
     * @param muleMessage
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @Processor(intercepting = true)
    public Object actAsRelyingParty(SourceCallback callback, MuleMessage muleMessage) {
		try {
			return callback.process(muleMessage.getPayload());
		} catch (Exception e) {
			return muleMessage.getPayload();
		}
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