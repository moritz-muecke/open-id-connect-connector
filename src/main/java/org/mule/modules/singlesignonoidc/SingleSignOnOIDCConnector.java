package org.mule.modules.singlesignonoidc;

import java.util.Map;
import javax.ws.rs.core.HttpHeaders;
import org.keycloak.common.VerificationException;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.callback.SourceCallback;
import org.mule.api.MuleMessage;
import org.mule.api.annotations.lifecycle.Start;
import org.mule.api.annotations.param.InboundHeaders;
import org.mule.modules.singlesignonoidc.client.OpenIDConnectClient;
import org.mule.modules.singlesignonoidc.config.ConnectorConfig;
import org.mule.modules.singlesignonoidc.exception.HeaderFormatException;

@Connector(name="oidc-token-validator", friendlyName="OIDCTokenValidator")
public class SingleSignOnOIDCConnector {

	private OpenIDConnectClient client;
	
	@Config
    ConnectorConfig config;
    
    @Start
    public void init() {
    	config.buildSsoUri();
    	client = new OpenIDConnectClient(config);
    }
    
    @Processor(intercepting = true)
    public Object onlineTokenValidation(SourceCallback callback, MuleMessage muleMessage, @InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers, String introspectionEndpoint) {
    	config.buildIntrospectionUri(introspectionEndpoint);
    	try {
			client.validateToken(headers.get(HttpHeaders.AUTHORIZATION), true);
			return callback.process(muleMessage.getPayload());
		} catch (HeaderFormatException e) {
			muleMessage.setOutboundProperty("http.status", 400);
			muleMessage.setPayload(e.getMessage());	
			return muleMessage.getPayload();
		} catch (Exception e) {
			muleMessage.setOutboundProperty("http.status", 500);
			muleMessage.setPayload(e.getMessage());	
			return muleMessage.getPayload();
		}
    }
    
    @Processor(intercepting = true)
    public Object localTokenValidation(SourceCallback callback, MuleMessage muleMessage, @InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers) {
    	try {
    		System.out.println(headers.toString());
			client.validateToken(headers.get(HttpHeaders.AUTHORIZATION), false);
			return callback.process(muleMessage.getPayload());
		} catch (HeaderFormatException e) {
			muleMessage.setOutboundProperty("http.status", 400);
			muleMessage.setPayload(e.getMessage());	
			return muleMessage.getPayload();
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