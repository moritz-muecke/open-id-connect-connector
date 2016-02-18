package org.mule.modules.oidctokenvalidator.client;

import org.mule.api.MuleEvent;
import org.mule.api.MuleMessage;
import org.mule.api.annotations.expressions.Mule;
import org.mule.api.store.ObjectStoreException;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.RequestTokenFromSsoException;

import java.util.Map;

public interface OpenIdConnectClient {

	Map<String, Object> ssoTokenValidation(String header) throws Exception;

	Map<String, Object> localTokenValidation(String header) throws Exception;

	boolean actAsRelyingParty(MuleMessage muleMessage) throws ObjectStoreException, RequestTokenFromSsoException;

	SingleSignOnConfig getSsoConfig();
}
