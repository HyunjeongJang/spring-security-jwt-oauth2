package com.web.security.common.helper;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.web.security.domain.type.MemberRole;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Component
public class JwtHelper {

    private static final int ACCESS_TOKEN_VALIDITY = 30 * 60 * 1000;

    private static final int REFRESH_TOKEN_VALIDITY = 24 * 60 * 60 * 1000;

    // 시크릿 키는 VERIFY SIGNATURE 를 암호화 하기 위해 쓰임
    // jwt secretKey 내가 만들어준 키로 토큰이 맞는지 검증 할 수 있음, 토큰은 인코딩 개념, 양방향 암호화가 아님
    @Value("${jwt.secret-key}") private String secretKey;

    public String generateAccessToken(String subject, String role) {
        // JWT => Token -> 여기에는 정보가 들어갈 수 있음 -> 이 정보는 Claim
        // Claim 에는 키를 넣을 수도 있고 기본적으로 제공하는 키워드들이 있음
        // 데이터가 암호화 되는게 아니라 민감한 정보를 넣으면 안되므로 멤버아이디, 권한만 넣음
        // https://jwt.io/#debugger-io
        return JWT.create()
                .withSubject(subject)
                .withClaim("role", role)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY))
                .sign(Algorithm.HMAC512(secretKey)); // 시크릿 키를 전달
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
        } catch (JWTVerificationException exception) {
            return false;
        }
        return true;
    }
}
