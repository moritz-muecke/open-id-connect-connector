package org.mule.modules.singlesignonoidc.exception;

public class MissingHeaderException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public MissingHeaderException(String message) {
		super(message);
	}
}
