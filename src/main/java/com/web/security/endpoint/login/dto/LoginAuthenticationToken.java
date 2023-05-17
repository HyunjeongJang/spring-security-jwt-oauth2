package com.web.security.endpoint.login.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.data.support.PageableExecutionUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

// 인증객체는 인증되기 전, 인증된 후 두 가지 상태를 가짐
public class LoginAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public LoginAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public LoginAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public static LoginAuthenticationToken beforeOf(LoginRequest req) {
        return new LoginAuthenticationToken(req.getEmail(), req.getPassword());
    }

    public static Authentication afterOf(String accessToken, String refreshToken) {
        JwtDto jwtDto = new JwtDto(accessToken, refreshToken);
        return new LoginAuthenticationToken(jwtDto, "", List.of());
    }

    public String getEmail() {
        return (String) this.getPrincipal();
    }

    public String getPassword() {
        return (String) this.getCredentials();
    }

    public String getAccessToken() {
        return ((JwtDto) this.getPrincipal()).getAccessToken();
    }

    public String getRefreshToken() {
        return ((JwtDto) this.getPrincipal()).getRefreshToken();
    }

    @Data
    @AllArgsConstructor
    static class JwtDto {
        private String accessToken;
        private String refreshToken;
    }
}
