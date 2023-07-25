package com.web.security.endpoint.jwtauth;

import com.web.security.security.exception.NotFoundAccessTokenException;
import com.web.security.endpoint.jwtauth.dto.JwtAuthentication;
import org.springframework.security.authentication.AuthenticationManager;
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

        String accessToken = Optional.ofNullable(request.getHeader("Authorization"))
                .map(header -> header.substring(AUTHORIZATION_HEADER_PREFIX.length()))
                .orElseThrow(NotFoundAccessTokenException::new);
        JwtAuthentication before = JwtAuthentication.beforeOf(accessToken);
        AuthenticationManager manager = super.getAuthenticationManager();
        return super.getAuthenticationManager().authenticate(before);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        JwtAuthentication afterOf = (JwtAuthentication) authResult;
        SecurityContextHolder.clearContext();
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(afterOf);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

}