package com.hwacom.recaptcha;

import jakarta.ws.rs.core.MultivaluedMap;

import java.io.IOException;

public class Utility {

    public static float createAssessment(String token) {
        float score = 0.0F;
        try {
            score = GoogleReCaptchaAssessment.createAssessment(token);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return score;
    }
}
