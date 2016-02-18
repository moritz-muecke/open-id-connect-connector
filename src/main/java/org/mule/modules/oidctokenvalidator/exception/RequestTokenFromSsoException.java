package org.mule.modules.oidctokenvalidator.exception;

/**
 * Created by moritz.moeller on 18.02.2016.
 */
public class RequestTokenFromSsoException extends Exception{
    public RequestTokenFromSsoException(String message) {
        super(message);
    }
}
