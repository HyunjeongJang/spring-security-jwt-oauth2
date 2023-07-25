package com.web.security.endpoint.jwtauth.dto;

import com.web.security.domain.type.MemberRole;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

public class JwtAuthentication extends UsernamePasswordAuthenticationToken {

    public JwtAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public JwtAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public static JwtAuthentication beforeOf(String accessToken) {
        return new JwtAuthentication(accessToken, "");
    }

    public static Authentication afterOf(long memberId, MemberRole role) {
        return new JwtAuthentication(memberId, "", List.of(role));
    }

    public String getAccessToken() {
        return (String) this.getPrincipal();
    }

}
