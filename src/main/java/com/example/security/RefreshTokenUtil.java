package com.example.security;

import java.security.SecureRandom;
import java.util.Base64;

public class RefreshTokenUtil {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64 = Base64.getUrlEncoder().withoutPadding();

    public static String generateToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return base64.encodeToString(randomBytes);
    }
}
