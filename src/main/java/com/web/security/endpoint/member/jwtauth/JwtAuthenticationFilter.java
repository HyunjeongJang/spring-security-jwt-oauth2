package com.web.security.endpoint.member.jwtauth;

import com.web.security.core.NotFoundAccessTokenException;
import com.web.security.endpoint.member.jwtauth.dto.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PushbackInputStream;
import java.util.Optional;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String AUTHORIZATION_HEADER_PREFIX = "BEARER";

    public JwtAuthenticationFilter(RequestMatcher requestMatcher) {
        super(requestMatcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // fe 에서 어떻게 AccessToken 을 넘겨줬느냐
        // 보통은 Request Header 를 통해서 넘겨주고 그 Header 의 이름은 Authorization
        // Authorization: Bearer 형태
        String accessToken = Optional.ofNullable(request.getHeader("Authorization"))
                .map(header -> header.substring(AUTHORIZATION_HEADER_PREFIX.length()))
                .orElseThrow(NotFoundAccessTokenException::new);

        JwtAuthenticationToken beforeToken = JwtAuthenticationToken.beforeOf(accessToken);
        return super.getAuthenticationManager().authenticate(beforeToken); // Authentication 객체를 넘겨야 함 (인증 전 객체)
    }

    // 생성자가 들어가야 하는데 로그인 같은 경우에는 경로가 하나니까 String 으로 받았는데
    // jwt url 을 거쳐야 하는 url은 무수히 많기 때문에 requestMatcher 라는걸 통해서 해당 요청이 필터를 타야하는지 안타야 하는지 검증해줌
}
