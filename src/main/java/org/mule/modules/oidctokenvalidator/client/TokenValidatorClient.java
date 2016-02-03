package org.mule.modules.oidctokenvalidator.client;

import java.util.Map;

public interface TokenValidatorClient {
	
	public Map<String, Object> ssoTokenValidation(String header) throws Exception;
	
	public Map<String,Object> localTokenValidation(String header) throws Exception;
	
}
