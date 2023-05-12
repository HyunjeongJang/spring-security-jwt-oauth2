/*
package com.web.security.security.handler;

import com.web.security.endpoint.jwtauth.dto.JwtAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    // LoginSuccessHandler 에선 끝났으면 사용자한테 가지만 이건 토큰 인증이 성공했으면 안으로 들어가야 하므로 체인에 doFilter 써서 다음으로 진행시켜줘야함
    // 종착지가 아니라 다음으로 진행시켜줘야 할 때
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
        // 인증객체 본모습은 JwtAuthenticationToken
        // 인증이 됐으니까 SuccessHandler 로 왔을 것
        JwtAuthenticationToken afterOf = (JwtAuthenticationToken) authentication;

        // SecurityContext 는 인증 객체가 저장되어 있는 공간
        // SecurityContextHolder 는 SecurityContext 에 전역적으로 접근할 수 있도록 해주는 객체
        SecurityContextHolder.clearContext();
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        // 인증 객체 넣어주기
        context.setAuthentication(afterOf);
        SecurityContextHolder.setContext(context);

        chain.doFilter(request, response);
    }

    // 이 메서드는 여기가 종착지 일 때
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

    }
}
*/
