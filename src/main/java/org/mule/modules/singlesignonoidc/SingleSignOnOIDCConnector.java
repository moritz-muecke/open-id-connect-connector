package org.mule.modules.singlesignonoidc;

import java.util.Map;

import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.HttpHeaders;

import org.apache.cxf.common.util.ReflectionInvokationHandler.Optional;
import org.mule.api.MuleMessage;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Configurable;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.callback.SourceCallback;
import org.mule.api.MuleEvent;
import org.mule.api.annotations.lifecycle.Start;
import org.mule.api.annotations.param.InboundHeaders;
import org.mule.modules.singlesignonoidc.client.OpenIDConnectClient;
import org.mule.modules.singlesignonoidc.config.ConnectorConfig;

@Connector(name="oidc-token-validator", friendlyName="OIDCTokenValidator")
public class SingleSignOnOIDCConnector {

	private OpenIDConnectClient client;
	
	@Config
    ConnectorConfig config;
    
    @Start
    public void init() {
    	this.client = new OpenIDConnectClient(this);
    }
   
    @Processor(intercepting = true)
    public Object redirectTest(SourceCallback callback, MuleEvent muleEvent, @Optional String token) throws Exception{
    	if (token.length() > 1) {
    		muleEvent.getMessage().setOutboundProperty("http.status", 200);
    		return callback.process(muleEvent.getMessage().getPayload());
    	} else {
    		muleEvent.getMessage().setOutboundProperty("http.status", 302);
    		return muleEvent.getMessage().getPayload();
    	}
    }
    
    @Processor
    public void onlineTokenValidation(@InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers, String introspectionEndpoint) {
    	client.onlineTokenValidation(headers.get(HttpHeaders.AUTHORIZATION));
    }
    
    @Processor
    public void localTokenValidation(@InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers) {
    	
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