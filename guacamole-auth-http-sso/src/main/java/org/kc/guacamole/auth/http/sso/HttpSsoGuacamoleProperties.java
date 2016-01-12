package org.kc.guacamole.auth.http.sso;

import org.glyptodon.guacamole.properties.StringGuacamoleProperty;


/**
 * Provides properties required for use of the HTTP SSO authentication provider.
 * These properties will be read from guacamole.properties when the HTTP SSO
 * authentication provider is used.
 *
 * @author Michael Jumper
 * @author Frank Kemmer
 */
public class HttpSsoGuacamoleProperties {

    /**
     * This class should not be instantiated.
     */
    private HttpSsoGuacamoleProperties() {}

    /**
     * The base DN to search for Guacamole configurations.
     */
    public static final StringGuacamoleProperty HTTP_SSO_REMOTE_USER_HEADER = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "http-sso-remote-user-header"; }

    };

}
