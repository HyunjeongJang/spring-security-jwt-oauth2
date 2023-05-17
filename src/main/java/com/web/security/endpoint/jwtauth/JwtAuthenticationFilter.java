package com.web.security.endpoint.jwtauth;

import com.web.security.security.exception.NotFoundAccessTokenException;
import com.web.security.endpoint.jwtauth.dto.JwtAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String AUTHORIZATION_HEADER_PREFIX = "Bearer ";

    public JwtAuthenticationFilter(RequestMatcher requestMatcher) {
        super(requestMatcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // fe 에서 어떻게 AccessToken 을 넘겨주는지에 따라 다름
        // 보통은 Request Header 를 통해서 넘겨주고 그 Header 의 이름은 Authorization
        // Authorization: Bearer ~~ 형태
        String accessToken = Optional.ofNullable(request.getHeader("Authorization"))
                .map(header -> header.substring(AUTHORIZATION_HEADER_PREFIX.length()))
                .orElseThrow(NotFoundAccessTokenException::new);

        JwtAuthenticationToken beforeToken = JwtAuthenticationToken.beforeOf(accessToken);
        return super.getAuthenticationManager().authenticate(beforeToken); // Authentication(인증 전 객체) 객체를 넘겨야 함
    }

    // 생성자가 들어가야 하는데 로그인 같은 경우에는 경로가 하나니까 String 으로 받았는데
    // jwt url 을 거쳐야 하는 url 은 무수히 많기 때문에 requestMatcher 라는걸 통해서 해당 요청이 필터를 타야하는지 안타야 하는지 검증해줌

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        JwtAuthenticationToken afterOf = (JwtAuthenticationToken) authResult;

        // SecurityContext 는 인증 객체가 저장되어 있는 공간
        // SecurityContextHolder 는 SecurityContext 에 전역적으로 접근할 수 있도록 해주는 객체
        SecurityContextHolder.clearContext();
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(afterOf);
        SecurityContextHolder.setContext(context);

        chain.doFilter(request, response);
    }

}
