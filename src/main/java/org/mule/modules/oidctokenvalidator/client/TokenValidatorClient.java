package org.mule.modules.oidctokenvalidator.client;

import java.util.Map;

public interface TokenValidatorClient {
	
	Map<String, Object> ssoTokenValidation(String header) throws Exception;
	
	Map<String,Object> localTokenValidation(String header) throws Exception;
	
}
