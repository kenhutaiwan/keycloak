package com.hwacom.forms.login.freemarker;

import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.models.KeycloakSession;
import org.keycloak.theme.Theme;

import java.util.Locale;
import java.util.Properties;

public class FreeMarkerLoginFormsProvider extends org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider {
    private static final Logger logger = Logger.getLogger(FreeMarkerLoginFormsProvider.class);

    private static final String RECAPTCHA_KEY_ID = "RECAPTCHA_KEY_ID";
    public FreeMarkerLoginFormsProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    protected void createCommonAttributes(Theme theme, Locale locale, Properties messagesBundle, UriBuilder baseUriBuilder, LoginFormsPages page) {
        logger.info("come into SmartqLasFreeMarkerLoginFormsProvider");
        super.createCommonAttributes(theme, locale, messagesBundle, baseUriBuilder, page);
        logger.info("realm != null : " + (realm != null));
        if (realm != null) {
            // 2024-04-10 Ken Hu Google reCAPTCHA
            String reCaptchaToken = (System.getenv(RECAPTCHA_KEY_ID) != null) ? System.getenv(RECAPTCHA_KEY_ID) : "";
            logger.info("get reCAPTCHA Key ID from environment: " + reCaptchaToken);
            attributes.put(RECAPTCHA_KEY_ID.toLowerCase(), reCaptchaToken);
        }
    }
}
