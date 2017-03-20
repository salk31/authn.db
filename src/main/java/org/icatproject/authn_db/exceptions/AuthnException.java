package org.icatproject.authn_db.exceptions;

@SuppressWarnings("serial")
public class AuthnException extends Exception {

	private int httpStatusCode;
	private String message;

	public AuthnException(int httpStatusCode, String message) {
		this.httpStatusCode = httpStatusCode;
		this.message = message;
	}

	public String getShortMessage() {
		return message;
	}

	public int getHttpStatusCode() {
		return httpStatusCode;
	}

	public String getMessage() {
		return "(" + httpStatusCode + ") : " + message;
	}

}
