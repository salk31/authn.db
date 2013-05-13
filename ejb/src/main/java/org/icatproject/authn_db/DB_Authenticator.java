package org.icatproject.authn_db;

import java.io.File;
import java.io.FileInputStream;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.core.IcatException;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_db.DB_Authenticator")
@Remote
@TransactionManagement(TransactionManagementType.BEAN)
public class DB_Authenticator implements org.icatproject.authentication.Authenticator {

	@PersistenceContext(unitName = "db_authn")
	private EntityManager manager;

	private org.icatproject.authentication.AddressChecker addressChecker;

	private String mechanism;

	private static final Logger log = Logger.getLogger(DB_Authenticator.class);

	@PostConstruct
	private void init() {
		File f = new File("authn_db.properties");
		Properties props = null;
		try {
			props = new Properties();
			props.load(new FileInputStream(f));
		} catch (Exception e) {
			String msg = "Unable to read property file " + f.getAbsolutePath() + "  "
					+ e.getMessage();
			log.fatal(msg);
			throw new IllegalStateException(msg);

		}
		String authips = props.getProperty("ip");
		if (authips != null) {
			try {
				addressChecker = new AddressChecker(authips);
			} catch (IcatException e) {
				String msg = "Problem creating AddressChecker with information from "
						+ f.getAbsolutePath() + "  " + e.getMessage();
				log.fatal(msg);
				throw new IllegalStateException(msg);
			}
		}
		// Note that the mechanism is optional
		mechanism = props.getProperty("mechanism");

		log.debug("Initialised DB_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr)
			throws IcatException {

		if (addressChecker != null) {
			if (!addressChecker.check(remoteAddr)) {
				throw new IcatException(IcatException.IcatExceptionType.SESSION,
						"authn_db does not allow log in from your IP address " + remoteAddr);
			}
		}

		String username = credentials.get("username");
		log.debug("login:" + username);

		if (username == null || username.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"username cannot be null or empty.");
		}
		String password = credentials.get("password");
		if (password == null || password.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"password cannot be null or empty.");
		}
		log.debug("Entitity Manager is " + manager);
		log.debug("Checking password against database");

		Passwd passwd = this.manager.find(Passwd.class, username);
		if (passwd == null) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"The username and password do not match");
		}

		if (!passwd.getEncodedPassword().equals(password)) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"The username and password do not match");
		}
		log.info(username + " logged in succesfully");
		return new Authentication(username, mechanism);
	}

}
