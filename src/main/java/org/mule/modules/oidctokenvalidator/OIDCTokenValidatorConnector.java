package org.mule.modules.oidctokenvalidator;
import java.net.URI;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.mule.api.MuleContext;
import org.mule.api.MuleEvent;
import org.mule.api.MuleMessage;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.display.Password;
import org.mule.api.annotations.lifecycle.Start;
import org.mule.api.annotations.param.InboundHeaders;
import org.mule.api.callback.SourceCallback;
import org.mule.api.store.ListableObjectStore;
import org.mule.api.store.ObjectStoreException;
import org.mule.module.http.api.HttpConstants;
import org.mule.modules.oidctokenvalidator.client.OpenIdConnectClient;
import org.mule.modules.oidctokenvalidator.client.oidc.*;
import org.mule.modules.oidctokenvalidator.config.ConnectorConfig;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.HTTPConnectException;
import org.mule.modules.oidctokenvalidator.exception.MetaDataInitializationException;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;


@Connector(name="oidc-token-validator", friendlyName="OIDCTokenValidator")
public class OIDCTokenValidatorConnector {

	private OpenIdConnectClient client;
    private SingleSignOnConfig ssoConfig;

	@Config
    ConnectorConfig config;

    @Inject
    MuleContext muleContext;

    @Start
    public void init() throws MetaDataInitializationException, ObjectStoreException {
        ssoConfig = new SingleSignOnConfig(config);
        TokenValidator validator = new TokenValidator(ssoConfig);
    	client = new OpenIdConnectClient(config, ssoConfig, validator);
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
            changeResponseStatus(muleMessage, Response.Status.UNAUTHORIZED);
			muleMessage.setPayload(e.getMessage());
			return muleMessage.getPayload();
		} catch (HTTPConnectException e) {
			changeResponseStatus(muleMessage, Response.Status.SERVICE_UNAVAILABLE);
            muleMessage.setPayload(e.getMessage());
			throw e;
		} catch (Exception e) {
			changeResponseStatus(muleMessage, Response.Status.BAD_REQUEST);
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
			changeResponseStatus(muleMessage, Response.Status.UNAUTHORIZED);
			muleMessage.setPayload(e.getMessage());	
			return muleMessage.getPayload();
		} catch (Exception e) {
            changeResponseStatus(muleMessage, Response.Status.BAD_REQUEST);
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
    public Object actAsRelyingParty(
            SourceCallback callback,
            MuleEvent muleEvent,
            String redirectUri,
            String clientId,
            @Password String clientSecret,
            boolean instantRefresh) throws Exception {
        MuleMessage muleMessage = muleEvent.getMessage();
        ClientSecretBasic clientSecretBasic = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
        client.getSsoConfig().setRedirectUri(new URI(redirectUri));
        client.getSsoConfig().setClientSecretBasic(clientSecretBasic);

        ListableObjectStore<String> tokenStore = muleContext.getObjectStoreManager().getObjectStore("token-cookie-store");
        Storage<String> tokenStorage = new TokenStorage(tokenStore);
        ListableObjectStore<RedirectData> redirectStore = muleContext.getObjectStoreManager().getObjectStore("redirect-cookie-store");
        Storage<RedirectData> redirectStorage = new RedirectDataStorage(redirectStore);
        TokenRequester requester = new TokenRequester(ssoConfig);
        RelyingPartyHandler handler = new RelyingPartyHandler(muleMessage, requester, tokenStorage, redirectStorage, instantRefresh);

        try {
            client.actAsRelyingParty(handler);

            int status = muleMessage.getOutboundProperty(HttpConstants.ResponseProperties.HTTP_STATUS_PROPERTY);

            if (status == HttpConstants.HttpStatus.MOVED_TEMPORARILY.getStatusCode()) {
                return muleMessage.getPayload();
            } else return callback.process(muleMessage);
        } catch (Exception e) {
            changeResponseStatus(muleMessage, Response.Status.INTERNAL_SERVER_ERROR);
            muleMessage.setPayload(e.getMessage());
            return muleMessage.getPayload();
        }
    }

	private void changeResponseStatus(MuleMessage message, Response.StatusType statusType) {
		message.setOutboundProperty(HttpConstants.ResponseProperties.HTTP_STATUS_PROPERTY, statusType.getStatusCode());
		message.setOutboundProperty(HttpConstants.ResponseProperties.HTTP_REASON_PROPERTY, statusType.getReasonPhrase());
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