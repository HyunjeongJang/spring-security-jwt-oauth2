package com.web.security.endpoint.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.web.security.endpoint.login.dto.LoginAuthenticationToken;
import com.web.security.endpoint.login.dto.LoginRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    // 사용자의 자격 증명 정보를 인증하는 기본 필터로 사용, AuthenticationEntryPoint로 자격 증명 정보를 요청하고 나면, AbstractAuthenticationProcessingFilter 가 인증 요청을 수행

    public LoginAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        // Login 요청이니까 email, password 가 request 의 Body 안에 들어있음
        LoginRequest loginRequest = new ObjectMapper().readValue(request.getReader(), LoginRequest.class);
        // Authentication 객체 (인증 전 객체)
        LoginAuthenticationToken beforeToken = LoginAuthenticationToken.beforeOf(loginRequest);
        return super.getAuthenticationManager().authenticate(beforeToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        LoginAuthenticationToken afterToken = (LoginAuthenticationToken) authResult;
        log.info("로그인 성공^^ AccessToken : " + afterToken.getAccessToken());
        super.successfulAuthentication(request, response, chain, authResult);
    }
}

