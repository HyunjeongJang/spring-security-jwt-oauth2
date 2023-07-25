package com.web.security.common.helper;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtHelper {

//    private static final int ACCESS_TOKEN_VALIDITY = 60 * 10 * 1000;
//    private static final int REFRESH_TOKEN_VALIDITY = 24 * 60 * 60 * 1000;
    @Value("${jwt.access-time}") private int ACCESS_TOKEN_VALIDITY;
    @Value("{jwt.refresh-time}") private int REFRESH_TOKEN_VALIDITY;
    @Value("${jwt.secret-key}") private String secretKey;

    public String generateAccessToken(String subject, String role) {
        return JWT.create()
                .withSubject(subject)
                .withClaim("role", role)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY))
                .sign(Algorithm.HMAC512(secretKey));
    }

    public String generateRefreshToken(String subject) {
        return JWT.create()
                .withSubject(subject)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY))
                .sign(Algorithm.HMAC512(secretKey));
    }

    public String extractSubject(String token) {
        return JWT.decode(token)
                .getSubject();
    }

    public long extractExpiredAt(String token) {
        return JWT.decode(token)
                .getExpiresAt()
                .getTime();
    }

    public String extractRole(String token) {
        return JWT.decode(token)
                .getClaim("role")
                .asString();
    }

    public boolean validate(String token) {
        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC512(secretKey)).build();
            verifier.verify(token);
        } catch (JWTVerificationException ex) {
            return false;
        }
        return true;
    }

}
