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
        // 인증 객체의 본모습-> JwtAuthenticationToken(업캐스팅 된 상태)
        JwtAuthentication before = (JwtAuthentication) authentication; // 인증 전 객체
//        String accessToken = (String) beforeToken.getPrincipal();

        // accessToken 이 올바른지 검증
        String accessToken = before.getAccessToken();

        // 블랙리스트 확인
        if (blackListRedisRepository.exists(accessToken)) {
            throw new BlackListedAccessTokenException(); // 부모로 AuthenticationException 을 가지고 있음(그래야 스프링 시큐리티에서 지원하는 방식으로 에러처리 가능)
        }
        // 형식이 올바른지 내가 만든 토큰이 맞는지 검증
        if (!jwtHelper.validate(accessToken)) { // 검증 실패
            throw new InvalidAccessTokenException(); // 실패하면 에러 발생
        }

        // 인증 성공했으면 인증 후 객체를 내려야 함
        // accessToken -> memberId(subject) role(role Claim)
        long memberId = Long.parseLong(jwtHelper.extractSubject(accessToken));
        MemberRole role = MemberRole.valueOf(jwtHelper.extractRole(accessToken));
        // 인증 후 객체 만들기 -> 인증 성공한 사용자 정보를 어딘가에 넣어둘것 이 필요하므로. 로그인 한 사용자가 누군지 알 필요가 있으니까 사용자 정보가 들어있음
        return JwtAuthentication.afterOf(memberId, role); // return 하면 successfulHandler 로 이동 (JwtAuthenticationFilter - successfulAuthentication)
    }

    @Override
    public boolean supports(Class<?> authentication) { // Provider 가 처리할 수 있는 인증객체를 지정해주는 역할
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }
}

// 1. 에러의 회피(Throws)
// 2. 에러의 전환(catch -> throw)
// 3. 에러의 회복(catch)
