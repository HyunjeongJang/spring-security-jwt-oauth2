package com.web.security.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.web.security.endpoint.login.dto.LoginAuthentication;
import com.web.security.endpoint.login.dto.LoginResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    // Provider 가 보내준거 객체는 -> LoginAuthentication 형태 -> UpCasting -> Authentication 이 됨
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth) throws IOException, ServletException {

        // Authentication auth 인증 객체가 옴 (Provider 가 return 한 객체) accessToken 과 refreshToken 이 담겨있는 // auth 는 객체 모양
        LoginAuthentication after = (LoginAuthentication) auth; // LoginAuthentication 실제 인스턴스의 모양 (Heap 메모리에 있는 모양) // 원래 모양으로 돌려줌
        String accessToken = after.getAccessToken();
        String refreshToken = after.getRefreshToken(); // 토큰 꺼내서

        LoginResponse loginResponse = new LoginResponse(accessToken, refreshToken); // 사용자에게 내림
        String body = new ObjectMapper().writeValueAsString(loginResponse);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().println(body); // 시용자의 responseBody 에 내가 가지고 있는 객체정보를 넣어줌
    }

}
