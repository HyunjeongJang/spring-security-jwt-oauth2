package com.web.security.endpoint.login.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

public class LoginAuthentication extends UsernamePasswordAuthenticationToken {

    public LoginAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public LoginAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public static LoginAuthentication beforeOf(LoginRequest req) {
        return new LoginAuthentication(req.getEmail(), req.getPassword());
    }

    public static Authentication afterOf(String accessToken, String refreshToken) {
        JwtDto jwtDto = new JwtDto(accessToken, refreshToken);
        return new LoginAuthentication(jwtDto, "", List.of());
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
