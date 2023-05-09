package com.web.security.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.web.security.endpoint.login.dto.LoginAuthenticationToken;
import com.web.security.endpoint.login.dto.LoginResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.io.IOException;

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth) throws IOException, ServletException {
        // access_token, refresh_token
        LoginAuthenticationToken afterToken = (LoginAuthenticationToken) auth;
        String accessToken = afterToken.getAcessToken();
        String refreshToken = afterToken.getRefreshToken();

        LoginResponse loginResponse = new LoginResponse(accessToken, refreshToken);
        String body = new ObjectMapper().writeValueAsString(loginResponse);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().println(body);
    }
}
