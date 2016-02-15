package org.mule.modules.oidctokenvalidator.client;

import org.mule.api.MuleMessage;
import org.mule.api.annotations.expressions.Mule;

import java.util.Map;

public interface OpenIdConnectClient {
	
	Map<String, Object> ssoTokenValidation(String header) throws Exception;
	
	Map<String,Object> localTokenValidation(String header) throws Exception;

    MuleMessage actAsRelyingParty(MuleMessage muleMessage);
}
