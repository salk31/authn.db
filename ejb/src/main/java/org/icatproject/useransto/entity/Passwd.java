package org.icatproject.useransto.entity;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.Id;

@SuppressWarnings("serial")
@Entity
public class Passwd implements Serializable {

	@SuppressWarnings("unused")
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
