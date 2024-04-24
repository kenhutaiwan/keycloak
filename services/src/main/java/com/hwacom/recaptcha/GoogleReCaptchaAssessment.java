package com.hwacom.recaptcha;

import com.google.cloud.recaptchaenterprise.v1.RecaptchaEnterpriseServiceClient;
import com.google.recaptchaenterprise.v1.Assessment;
import com.google.recaptchaenterprise.v1.CreateAssessmentRequest;
import com.google.recaptchaenterprise.v1.Event;
import com.google.recaptchaenterprise.v1.ProjectName;
import com.google.recaptchaenterprise.v1.RiskAnalysis.ClassificationReason;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.Arrays;

public class GoogleReCaptchaAssessment {
    private static final Logger logger = Logger.getLogger(GoogleReCaptchaAssessment.class);
    private static final String PROJECT_ID = System.getenv("GOOGLE_PROJECT_ID");
    private static final String RECAPTCHA_KEY_ID = System.getenv("RECAPTCHA_KEY_ID");
    private static final String[] RECAPTCHA_ACTIONS = {"LOGIN", "UPDATE_PASSWORD"};

    /**
     * Create an assessment to analyze the risk of a UI action.
     *
     * @param token : The generated token obtained from the client.
     */
    public static float createAssessment(String token) throws IOException {
        // Create the reCAPTCHA client.
        // TODO: Cache the client generation code (recommended) or call client.close() before exiting the method.
        try (RecaptchaEnterpriseServiceClient client = RecaptchaEnterpriseServiceClient.create()) {

            // Set the properties of the event to be tracked.
            Event event = Event.newBuilder().setSiteKey(RECAPTCHA_KEY_ID).setToken(token).build();

            // Build the assessment request.
            CreateAssessmentRequest createAssessmentRequest =
                    CreateAssessmentRequest.newBuilder()
                            .setParent(ProjectName.of(PROJECT_ID).toString())
                            .setAssessment(Assessment.newBuilder().setEvent(event).build())
                            .build();

            Assessment response = client.createAssessment(createAssessmentRequest);

            // Check if the token is valid.
            if (!response.getTokenProperties().getValid()) {
                logger.info(
                        "The CreateAssessment call failed because the token was: "
                                + response.getTokenProperties().getInvalidReason().name());
                return 0;
            }

            // Check if the expected action was executed.
            // Arrays.stream(array).anyMatch(s -> s.equals(str))
            if (!Arrays.stream(RECAPTCHA_ACTIONS).anyMatch(s -> s.equals(response.getTokenProperties().getAction()))) {
                logger.info(
                        "The action attribute in reCAPTCHA tag is: "
                                + response.getTokenProperties().getAction());
                logger.info(
                        "The action attribute in the reCAPTCHA tag "
                                + "does not match the action ("
                                + String.join(",", RECAPTCHA_ACTIONS)
                                + ") you are expecting to score");
                return 0;
            }

            // Get the risk score and the reason(s).
            // For more information on interpreting the assessment, see:
            // https://cloud.google.com/recaptcha-enterprise/docs/interpret-assessment
            for (ClassificationReason reason : response.getRiskAnalysis().getReasonsList()) {
                logger.info(reason.toString());
            }

            float recaptchaScore = response.getRiskAnalysis().getScore();
            logger.info("The reCAPTCHA score is: " + recaptchaScore);

            // Get the assessment name (id). Use this to annotate the assessment.
            String assessmentName = response.getName();
            logger.info(
                    "Assessment name: " + assessmentName.substring(assessmentName.lastIndexOf("/") + 1));

            return recaptchaScore;
        }
    }
}
