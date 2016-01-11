package org.mule.modules.singlesignonoidc;

import java.util.Map;

import javax.ws.rs.core.HttpHeaders;

import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
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
   
    @Processor
    public void onlineTokenValidation(@InboundHeaders(HttpHeaders.AUTHORIZATION) Map<String, String> headers) {
    	client.onlineTokenValidation(headers.get(HttpHeaders.AUTHORIZATION));
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