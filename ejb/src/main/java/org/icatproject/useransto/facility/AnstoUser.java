package org.icatproject.useransto.facility;

import java.util.Map;

import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.icatproject.core.IcatException;
import org.icatproject.core.authentication.Authenticator;
import org.icatproject.useransto.entity.Passwd;

@Stateless()
@Remote(Authenticator.class)
@TransactionManagement(TransactionManagementType.BEAN)
public class AnstoUser implements Authenticator {

	@PersistenceContext(unitName = "icatuser")
	private EntityManager manager;

	private static final Logger log = Logger.getLogger(AnstoUser.class);

	public AnstoUser() {
		// File f = new File("icat.properties");
		// try {
		// Properties props = new Properties();
		// props.load(new FileInputStream(f));
		// String authips = props.getProperty("auth.ansto.ip");
		// if (authips != null) {
		// anstoAddressChecker = new AddressChecker(authips);
		// }
		// } catch (Exception e) {
		// icatInternalException = new IcatException(IcatException.IcatExceptionType.INTERNAL,
		// "Problem with "
		// + f.getAbsolutePath() + "  " + e.getMessage());
		// log.fatal("Problem with " + f.getAbsolutePath() + "  " + e.getMessage());
		// }
		log.trace("Created AnstoUser with Entitity Manager" + manager);
	}

	// if (anstoAddressChecker != null) {
	// if (!anstoAddressChecker.check(req.getRemoteAddr())) {
	// throw new IcatException(IcatException.IcatExceptionType.SESSION,
	// "You may not log in by 'ansto' from your IP address " + req.getRemoteAddr());
	// }
	// }

	@Override
	public Authentication login(Map<String, String> credentials) throws IcatException {
		String username = credentials.get("username");
		log.trace("login:" + username);

		if (username == null || username.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Username cannot be null or empty.");
		}
		String password = credentials.get("password");
		if (password == null || password.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Password cannot be null or empty.");
		}
		log.trace("Entitity Manager is " + manager);
		log.info("Checking password against database");

		Passwd passwd = this.manager.find(Passwd.class, username);
		if (passwd == null) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Username and password do not match");
		}

		if (!passwd.getEncodedPassword().equals(password)) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Username and password do not match");
		}

		return new Authentication(username, AnstoUser.class.getName());
	}

}
