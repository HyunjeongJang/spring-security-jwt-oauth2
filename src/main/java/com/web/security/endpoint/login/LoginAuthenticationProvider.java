package com.web.security.endpoint.login;

import com.web.security.common.helper.JwtHelper;
import com.web.security.domain.service.RefreshTokenRedisService;
import com.web.security.endpoint.login.dto.LoginAuthentication;
import com.web.security.security.entity.MemberSecurityEntity;
import com.web.security.security.service.MemberSecurityService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class LoginAuthenticationProvider implements AuthenticationProvider {

    private final MemberSecurityService memberSecurityService;
    private final JwtHelper jwtHelper;
    private final RefreshTokenRedisService refreshTokenRedisService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginAuthentication before = (LoginAuthentication) authentication;
        MemberSecurityEntity user = (MemberSecurityEntity) memberSecurityService.loadUserByUsername(before.getEmail());
        user.validatePassword(passwordEncoder, before.getPassword());
        String accessToken = jwtHelper.generateAccessToken(user.getUsername(), user.getRoleName());
        String refreshToken = jwtHelper.generateRefreshToken(user.getUsername());
        refreshTokenRedisService.save(refreshToken);
        return LoginAuthentication.afterOf(accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return LoginAuthentication.class.isAssignableFrom(authentication);
    }

}
