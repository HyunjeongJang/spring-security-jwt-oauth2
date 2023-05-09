package com.web.security.endpoint.login;

import com.web.security.endpoint.login.dto.LoginAuthenticationToken;
import com.web.security.endpoint.login.service.MemberSecurityService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class LoginAuthenticationProvider implements AuthenticationProvider {

    // 로그인을 처리하려면 DB가 필요
    private final MemberSecurityService memberSecurityService;

    // TODO: Redis 관련작업

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginAuthenticationToken beforeToken = (LoginAuthenticationToken) authentication;
        UserDetails userDetails = memberSecurityService.validate(beforeToken.getEmail(), beforeToken.getPassword());
        // TODO: Login 성공 -> AccessToken, RefreshToken
        // TODO: RefreshToken 을 Redis 에 저장
        return LoginAuthenticationToken.afterOf("access_token", "refresh_token");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return LoginAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
