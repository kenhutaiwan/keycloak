package com.hwacom.authentication.authenticators.browser;

import com.hwacom.recaptcha.Utility;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

public class UsernamePasswordForm extends org.keycloak.authentication.authenticators.browser.UsernamePasswordForm{
    private static final Logger logger = Logger.getLogger(UsernamePasswordForm.class);
    private float score_lower_limit = 0.0F;

    public UsernamePasswordForm() {
        super();
        if (System.getenv("RECAPTCHA_SCORE_THRESHOLD") != null) {
            score_lower_limit = Float.parseFloat(System.getenv("RECAPTCHA_SCORE_THRESHOLD"));
        }
    }

    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        String recaptcha_token = formData.getFirst("google_recaptcha_token");
        logger.info("get google reCAPTCHA token: " + recaptcha_token);

        if (recaptcha_token != null) {
            float score = Utility.createAssessment(recaptcha_token);
            logger.infof("recaptcha score is: %f", score);
            formData.add("score", "" + score);
        }
        return super.validateForm(context, formData);
    }

    // 2024-04-11 Ken hu: copy from org.keycloak.authentication.authenticators.browserAbstractUsernameFormAuthenticator
    private UserModel getUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        if (isUserAlreadySetBeforeUsernamePasswordAuth(context)) {
            // Get user from the authentication context in case he was already set before this authenticator
            UserModel user = context.getUser();
            testInvalidUser(context, user);
            return user;
        } else {
            // Normal login. In this case this authenticator is supposed to establish identity of the user from the provided username
            context.clearUser();
            return getUserFromForm(context, inputData);
        }
    }

    // 2024-04-11 Ken hu: copy from org.keycloak.authentication.authenticators.browserAbstractUsernameFormAuthenticator
    private UserModel getUserFromForm(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        if (username == null || username.isEmpty()) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return null;
        }

        // remove leading and trailing whitespace
        username = username.trim();

        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        UserModel user = null;
        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);

            // Could happen during federation import
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }
            return user;
        }

        testInvalidUser(context, user);
        return user;
    }

    @Override
    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData)  {
        UserModel user = getUser(context, inputData);
        boolean originalValidationResult = super.validateUserAndPassword(context, inputData);
        // 2024-04-11 Ken Hu: deny access if reCAPTCHA score below threshold
        return originalValidationResult && validateScore(context, inputData, user);
    }

    private boolean validateScore(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData, UserModel user) {
        // pass if no reCAPTCHA provided
        if (!inputData.containsKey("score")) return true;

        float score = Float.parseFloat(inputData.getFirst("score"));
        logger.info("score in validatePassword is: " + score);

        if (score < score_lower_limit) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = challenge(context, "lowReCaptchaScoreMessage", "google_recaptcha_token");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            return false;
        }
        return true;
    }
}
