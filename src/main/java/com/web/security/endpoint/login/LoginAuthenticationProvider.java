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


    // LoginAuthentication before 객체 형태로 넘겨줬는데 파라미터가 authentication 이 가능한 이유 -> Upcasting (자동)
    // 상속 : 부모 - 자식 / 부모가 가진걸 자식이 물려받는다. -> 자식이 부모가 할 수 있는 일을 모두 대체할 수 있다.(부모가 할 수 있는일은 자식이 다 할 수 있음)
    // 반드시 authentication 을 부모로 가지고 있어야 하는 이유 (그래야 프로다이더의 이 자리로 들어올 수 있음)
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginAuthentication before = (LoginAuthentication) authentication;
        // 부모 모양에서는 쓸 수 없기 때문에 다운캐스팅(강제 형변환)

        // 사용자가 준 이메일,패스워드가 올바른지 인증(이메일로 사용자정보 찾아와. 패스워드 일치하는지 확인) 비지니스 로직
        MemberSecurityEntity user = (MemberSecurityEntity) memberSecurityService.loadUserByUsername(before.getEmail());
        user.validatePassword(passwordEncoder, before.getPassword());

        // 인증 성공 했으면 (실패 했으면 에러가 발생했을거니까)
        // AccessToken -> 권한 관련된게 들어가있어야 함, accessToken 을 가지고 인가를 처리
        String accessToken = jwtHelper.generateAccessToken(user.getUsername(), user.getRoleName());
        // RefreshToken -> user 확인용
        String refreshToken = jwtHelper.generateRefreshToken(user.getUsername());
        // RefreshToken 을 Redis 에 저장
        refreshTokenRedisService.save(refreshToken);
        return LoginAuthentication.afterOf(accessToken, refreshToken); // 인증 후 객체
        // 로그인성공시 LoginSuccessHandler 를 타고 응답 리스폰스 바디에 넘어옴
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return LoginAuthentication.class.isAssignableFrom(authentication);
    }
}
