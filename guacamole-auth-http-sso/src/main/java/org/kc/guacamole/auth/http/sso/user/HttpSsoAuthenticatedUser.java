package org.kc.guacamole.auth.http.sso.user;

import org.glyptodon.guacamole.net.auth.AbstractAuthenticatedUser;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Credentials;

import com.google.inject.Inject;

/**
 * An HTTP-SSO-specific implementation of AuthenticatedUser, associating a
 * particular set of credentials with the HTTP SSO authentication provider.
 *
 * @author Michael Jumper
 * @author Frank Kemmer
 */
public class HttpSsoAuthenticatedUser extends AbstractAuthenticatedUser {

    /**
     * Reference to the authentication provider associated with this
     * authenticated user.
     */
    @Inject
    private AuthenticationProvider authProvider;

    /**
     * The credentials provided when this user was authenticated.
     */
    private Credentials credentials;

    /**
     * Initializes this AuthenticatedUser using the given credentials.
     *
     * @param credentials
     *     The credentials provided when this user was authenticated.
     */
    public void init(Credentials credentials) {
        this.credentials = credentials;
        setIdentifier(credentials.getUsername());
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Credentials getCredentials() {
        return credentials;
    }

}
