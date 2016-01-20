package org.mule.modules.singlesignonoidc.client;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.mule.modules.singlesignonoidc.SingleSignOnOIDCConnector;

public class OpenIDConnectClient {
	
	private SingleSignOnOIDCConnector connector;
	private Client client;
	private WebTarget ssoTarget;
	
	public OpenIDConnectClient(SingleSignOnOIDCConnector connector) {
		this.connector = connector;
		this.client = ClientBuilder.newClient();
		String ssoUrl = connector.getConfig().getSsoUri() + ":" + connector.getConfig().getSsoPort() + connector.getConfig().getSsoBasePath();
		this.ssoTarget = client.target(ssoUrl);
	}
	
	public void onlineTokenValidation(String token) {
		WebTarget target = ssoTarget
				.path(connector.getConfig().getTokenIntrospectionEndpoint())
				.queryParam("access_token", token);
		Invocation.Builder invocationBuilder = target.request(MediaType.APPLICATION_JSON);
		Response response = invocationBuilder.get();
		System.out.println(response.getStatus());
	}
	
	public SingleSignOnOIDCConnector getConnector() {
		return connector;
	}

	public void setConnector(SingleSignOnOIDCConnector connector) {
		this.connector = connector;
	}
}

