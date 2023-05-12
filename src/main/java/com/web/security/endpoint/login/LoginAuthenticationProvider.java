package com.web.security.endpoint.login;

import com.web.security.common.helper.JwtHelper;
import com.web.security.domain.service.RefreshTokenRedisService;
import com.web.security.endpoint.login.dto.LoginAuthenticationToken;
import com.web.security.endpoint.login.dto.MemberSecurityEntity;
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

    private final MemberSecurityService memberSecurityService;
    private final JwtHelper jwtHelper;
    private final RefreshTokenRedisService refreshTokenRedisService;

    // TODO: Redis 관련작업

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginAuthenticationToken beforeToken = (LoginAuthenticationToken) authentication;

        MemberSecurityEntity user = (MemberSecurityEntity) memberSecurityService.validate(beforeToken.getEmail(), beforeToken.getPassword());

        // AccessToken -> 권한 관련된게 들어가있어야 함, accessToken 을 가지고 인가를 처리
        String accessToken = jwtHelper.generateAccessToken(user.getUsername(), user.getRoleName());
        // RefreshToken -> user 확인용
        String refreshToken = jwtHelper.generateRefreshToken(user.getUsername());

        // RefreshToken 을 Redis 에 저장
        refreshTokenRedisService.save(refreshToken);
        return LoginAuthenticationToken.afterOf(accessToken, refreshToken);
        // 로그인성공시 LoginSuccessHandler 를 타고 응답 리스폰스 바디에 넘어옴
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return LoginAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
