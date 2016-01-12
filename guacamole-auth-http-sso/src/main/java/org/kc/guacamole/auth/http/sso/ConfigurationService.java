package org.kc.guacamole.auth.http.sso;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;

import com.google.inject.Inject;

/**
 * Service for retrieving configuration information regarding the LDAP server.
 *
 * @author Michael Jumper
 * @author Frank Kemmer
 */
public class ConfigurationService {

    /**
     * The Guacamole server environment.
     */
    @Inject
    private Environment environment;

    /**
     * Returns the name of the header attribute which contains
     * the user name authenticated by the SSO proxy. Configured
     * in guacamole.properties. If this property is empty, the
     * HttpServletRequest method:
     * <ul>
     *    <li>{@link javax.servlet.HttpServletRequest.getRemoteUser()}
     * </ul>
     * will be used. Otherwise the value of:
     * <ul>
     *    <li>{@link javax.servlet.HttpServletRequest.getHeader(<REMOTE_USER_HEADER>)}
     * </ul>
     * will be used to get the authenticated user name
     *
     * @return
     *     The name of the header attribute to get the authenticated
     *     user name, as configured with
     *     guacamole.properties or an empty string or null
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getHttpSsoRemoteUserHeader() throws GuacamoleException {
        return environment.getProperty(
            HttpSsoGuacamoleProperties.HTTP_SSO_REMOTE_USER_HEADER,
            null
        );
    }

}
