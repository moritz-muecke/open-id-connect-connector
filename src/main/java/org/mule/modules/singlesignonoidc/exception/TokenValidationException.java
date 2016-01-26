package org.mule.modules.singlesignonoidc.exception;

public class TokenValidationException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public TokenValidationException(String message) {
		super(message);
	}
}
