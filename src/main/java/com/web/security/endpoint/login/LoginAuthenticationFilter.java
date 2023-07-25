package com.web.security.endpoint.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.web.security.endpoint.login.dto.LoginAuthentication;
import com.web.security.endpoint.login.dto.LoginRequest;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public LoginAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {

        LoginRequest loginRequest = new ObjectMapper().readValue(request.getReader(), LoginRequest.class);
        LoginAuthentication before = LoginAuthentication.beforeOf(loginRequest);

        return super.getAuthenticationManager().authenticate(before);
    }

}
