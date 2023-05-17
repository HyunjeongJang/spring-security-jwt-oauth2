package com.web.security.endpoint.jwtauth;

import com.web.security.common.helper.JwtHelper;
import com.web.security.domain.repository.BlackListRedisRepository;
import com.web.security.domain.type.MemberRole;
import com.web.security.endpoint.jwtauth.dto.JwtAuthenticationToken;
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
        // 인증 객체의 본모습-> JwtAuthenticationToken(업캐스팅 된 상태)
        JwtAuthenticationToken beforeToken = (JwtAuthenticationToken) authentication; // 인증 전 객체
//        String accessToken = (String) beforeToken.getPrincipal();
        String accessToken = beforeToken.getAccessToken();

        if (blackListRedisRepository.exists(accessToken)) {
            throw new BlackListedAccessTokenException();
        }
        
        // 형식이 올바른지 내가 만든 토큰이 맞는지 검증
        try {
            if (!jwtHelper.validate(accessToken)) { // 검증 실패
                throw new InvalidAccessTokenException();
            }
            // accessToken -> memberId(subject) role(role Claim)
            long memberId = Long.parseLong(jwtHelper.extractSubject(accessToken));
            MemberRole role = MemberRole.valueOf(jwtHelper.extractRole(accessToken));
            // 인증 후 객체 만들기
            return JwtAuthenticationToken.afterOf(memberId, role);
        } catch (RuntimeException ex) { // 예기치 못한 에러, 에러의 전환일 때, 전환하기 전에 발생한 에러의 정보를 남기고 싶을때 중첩 시키고 싶을때 -> cause
            // 에러의 전환
            throw new InvalidAccessTokenException(ex);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) { // Provider 가 처리할 수 있는 인증객체를 지정해주는 역할
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

// 1. 에러의 회피(Throws)
// 2. 에러의 전환(catch -> throw)
// 3. 에러의 회복(catch)
