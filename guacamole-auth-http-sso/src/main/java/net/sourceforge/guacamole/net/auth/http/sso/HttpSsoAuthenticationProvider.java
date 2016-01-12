/*
 * Copyright (C) 2013 Glyptodon LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package net.sourceforge.guacamole.net.auth.http.sso;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.UserContext;
import org.kc.guacamole.auth.http.sso.ConfigurationService;
import org.kc.guacamole.auth.http.sso.HttpSsoAuthenticationProviderModule;
import org.kc.guacamole.auth.http.sso.user.HttpSsoAuthenticatedUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Provider;

import javax.servlet.http.HttpServletRequest;


/**
 * This authentication provider reads the username of a user authenticated
 * through a Single-Sign-On Security Proxy sitting in front of guacamole.
 * <p>
 * Usually the authenticating proxy sets the CGI Variable REMOTE_USER.
 * This variable can be read by the method:
 * <ul>
 *    <li>{@link javax.servlet.HttpServletRequest.getRemoteUser()}
 * </ul>
 * If the given Single-Sign-On Security Proxy uses a different header field,
 * the corresponding header field name can be given by a guacamole property
 * in the configuration. The name of this property is:
 * <ul>
 *    <li>http-sso-remote-user-header
 * </ul>   
 * In this case the username will be extracted by reading out that header with:
 * <ul>
 *    <li>{@link javax.servlet.HttpServletRequest.getHeader(<REMOTE_USER_HEADER>)}
 * </ul>
 * The given username will be set in the credentials for other authentication
 * providers to use.
 * <p>
 * This authentication provider will not return any further information. It justs
 * sets the username in the credentials and only returns an empty user context
 * <p>
 * The idea behind this authentication provider is, that other authentication
 * providers following behind, can read the username as usual from the given
 * credentials and take that user as authenticated for granted. This splits
 * authentication (checking the identity of the user) from authorization (reading
 * connection configurations)(following the pattern "Separation Of
 * Concerns").
 * 
 * @author Michael Jumper
 * @author Frank Kemmer
 */
public class HttpSsoAuthenticationProvider implements AuthenticationProvider {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(HttpSsoAuthenticationProvider.class);

    /**
     * Injector which will manage the object graph of this authentication
     * provider (IoC).
     */
    private final Injector injector;

    /**
     * Service for retrieving HTTP SSO configuration information.
     */
    // @Inject
    private ConfigurationService confService;
    
    /**
     * Provider for AuthenticatedUser objects.
     */
    // @Inject
    private Provider<HttpSsoAuthenticatedUser> authenticatedUserProvider;

    /**
     * Creates a new HttpSsoAuthenticationProvider that authenticates users
     * against an HTTP SSO header given by a Single-Sign-On Proxy in front of
     * guacamole.
     *
     * @throws GuacamoleException
     *     If a required property is missing, or an error occurs while parsing
     *     a property.
     */
    public HttpSsoAuthenticationProvider() throws GuacamoleException {

        // Set up Guice injector.
        injector = Guice.createInjector(
            new HttpSsoAuthenticationProviderModule(this)
        );
        
        confService = injector.getInstance(ConfigurationService.class);
        authenticatedUserProvider = injector.getProvider(HttpSsoAuthenticatedUser.class);

    }

    @Override
	public String getIdentifier() {
		return "httpsso";
	}

	@Override
	public AuthenticatedUser authenticateUser(Credentials credentials) throws GuacamoleException {
		HttpServletRequest request = credentials.getRequest();
		String username = null;
		String remoteUserHeader = confService.getHttpSsoRemoteUserHeader();
		if (remoteUserHeader == null || remoteUserHeader.length() == 0)  {
			logger.debug("Using getRemoteUser() to read SSO name");
			username = request.getRemoteUser();
		}
		else {
			logger.debug("Using getHeader(\"" + remoteUserHeader + "\") to read SSO name");
			username = request.getHeader(remoteUserHeader);
		}
		
		// No header => not authenticated
		if (username == null) {
			logger.info("Remote user not found => authentication denied!");
			return null;
		}

		// Authenticated with name given by header entry
		logger.info("Remote user `" + username + "' authenticated.");
		credentials.setUsername(username);
		HttpSsoAuthenticatedUser authenticatedUser = authenticatedUserProvider.get();
        authenticatedUser.init(credentials);
        return authenticatedUser;
	}

	@Override
	public AuthenticatedUser updateAuthenticatedUser(AuthenticatedUser authenticatedUser, Credentials credentials)
			throws GuacamoleException {
		return authenticatedUser;
	}

	@Override
	public UserContext getUserContext(AuthenticatedUser authenticatedUser) throws GuacamoleException {
		return null;
	}

	@Override
	public UserContext updateUserContext(UserContext context, AuthenticatedUser authenticatedUser)
			throws GuacamoleException {
		return context;
	}
	
}