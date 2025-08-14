package com.hwacom.authentication.requiredactions;

import com.hwacom.recaptcha.Utility;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import com.hwacom.recaptcha.GoogleReCaptchaAssessment;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.IOException;

public class UpdatePassword extends org.keycloak.authentication.requiredactions.UpdatePassword{
    private static final Logger logger = Logger.getLogger(UpdatePassword.class);
    private float score_lower_limit = 0.0F;

    public UpdatePassword() {
        super();
        if (System.getenv("RECAPTCHA_SCORE_THRESHOLD") != null) {
            score_lower_limit = Float.parseFloat(System.getenv("RECAPTCHA_SCORE_THRESHOLD"));
        }
    }

    public UpdatePassword(KeycloakSession session) {
        super(session);
        if (System.getenv("RECAPTCHA_SCORE_THRESHOLD") != null) {
            score_lower_limit = Float.parseFloat(System.getenv("RECAPTCHA_SCORE_THRESHOLD"));
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        event.event(EventType.UPDATE_PASSWORD);
        EventBuilder errorEvent = event.clone().event(EventType.UPDATE_PASSWORD_ERROR)
                .client(authSession.getClient())
                .user(authSession.getAuthenticatedUser());
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String recaptcha_token = formData.getFirst("google_recaptcha_token");
        logger.infof("get google reCAPTCHA token: %s", recaptcha_token);

        if (recaptcha_token != null && !recaptcha_token.isEmpty()) {
            float score = Utility.createAssessment(recaptcha_token);
            logger.infof("recaptcha score is: %f", score);

            if (score < score_lower_limit) {
                Response challenge = context.form()
                        .addError(new FormMessage("google_recaptcha_token", "lowReCaptchaScoreMessage"))
                        .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
                context.challenge(challenge);
                errorEvent.error(Errors.PASSWORD_MISSING);
                return;
            }
        }
        super.processAction(context);
    }
}
