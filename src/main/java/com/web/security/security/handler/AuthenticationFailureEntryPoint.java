package com.web.security.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

// AuthenticationEntryPoint -> 실패한 모든 exception 이 여기로 모이도록
@Slf4j
@Component
public class AuthenticationFailureEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        log.warn("사용자 인증 실패", authException);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // try - resources
        try (OutputStream outputStream = response.getOutputStream()) {
            new ObjectMapper().writeValue(outputStream, authException.getMessage());
            outputStream.flush();
        }
    }
}
// AuthenticationException authException 여기에 NotFoundJwtAccessToken~~ 객체가 옴 업캐스팅 됨(부모클래스)

