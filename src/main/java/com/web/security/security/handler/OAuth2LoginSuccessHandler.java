package com.web.security.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.web.security.common.helper.JwtHelper;
import com.web.security.domain.service.RefreshTokenRedisService;
import com.web.security.endpoint.login.dto.LoginResponse;
import com.web.security.endpoint.oauth2.dto.MyOAuth2User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtHelper jwtHelper;
    private final RefreshTokenRedisService refreshTokenRedisService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth) throws IOException, ServletException {

        MyOAuth2User user = (MyOAuth2User) auth.getPrincipal();
        String subject = String.valueOf(user.getMemberId());

        String accessToken = jwtHelper.generateAccessToken(subject, user.getRole().name());
        String refreshToken = jwtHelper.generateRefreshToken(subject);
        refreshTokenRedisService.save(refreshToken);

        LoginResponse loginResponse = new LoginResponse(accessToken, refreshToken);
        String body = new ObjectMapper().writeValueAsString(loginResponse);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().println(body);

    }
}
