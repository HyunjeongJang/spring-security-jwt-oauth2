package com.web.security.endpoint.jwtauth;

import com.web.security.common.helper.JwtHelper;
import com.web.security.domain.repository.BlackListRedisRepository;
import com.web.security.domain.type.MemberRole;
import com.web.security.endpoint.jwtauth.dto.JwtAuthentication;
import com.web.security.security.exception.BlackListedAccessTokenException;
import com.web.security.security.exception.InvalidAccessTokenException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtHelper jwtHelper;
    private final BlackListRedisRepository blackListRedisRepository;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        JwtAuthentication before = (JwtAuthentication) authentication;
        String accessToken = before.getAccessToken();
        if (blackListRedisRepository.exists(accessToken)) {
            throw new BlackListedAccessTokenException();
        }
        if (!jwtHelper.validate(accessToken)) {
            throw new InvalidAccessTokenException();
        }

        long memberId = Long.parseLong(jwtHelper.extractSubject(accessToken));
        MemberRole role = MemberRole.valueOf(jwtHelper.extractRole(accessToken));
        return JwtAuthentication.afterOf(memberId, role);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }

}