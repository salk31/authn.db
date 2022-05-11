package org.icatproject.authn_db;

import java.io.Serializable;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@SuppressWarnings("serial")
@Entity
public class Passwd implements Serializable {

	@Id
	private String userName;

	private String encodedPassword;

	// Needed by JPA
	public Passwd() {
	}

	public String getEncodedPassword() {
		return encodedPassword;
	}
}
