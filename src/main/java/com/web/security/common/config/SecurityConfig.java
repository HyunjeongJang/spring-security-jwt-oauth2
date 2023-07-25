package com.web.security.common.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.web.security.common.matcher.FilterSkipMatcher;
import com.web.security.endpoint.jwtauth.JwtAuthenticationFilter;
import com.web.security.endpoint.jwtauth.JwtAuthenticationProvider;
import com.web.security.endpoint.login.LoginAuthenticationFilter;
import com.web.security.endpoint.login.LoginAuthenticationProvider;
import com.web.security.endpoint.oauth2.service.MyOAuth2UserService;
import com.web.security.security.handler.AuthenticationFailureEntryPoint;
import com.web.security.security.handler.CustomAccessDeniedHandler;
import com.web.security.security.handler.LoginSuccessHandler;
import com.web.security.security.handler.OAuth2LoginSuccessHandler;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private static final List<String> JWT_AUTH_WHITELIST_SWAGGER = List.of("/v2/api-docs", "/configuration/ui", "/swagger-resources/**",
            "/configuration/security", "/swagger-ui.html/**", "/swagger-ui/**", "/webjars/**", "/swagger/**");
    private static final List<String> JWT_AUTH_WHITELIST_DEFAULT = List.of("/", "/member/register", "/error", "/login", "/oauth2/**", "/jwt/auth/access-token");

    private final MyOAuth2UserService oAuth2UserService;
    private final LoginSuccessHandler loginSuccessHandler;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final AuthenticationFailureEntryPoint authenticationFailureEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final LoginAuthenticationProvider loginAuthenticationProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    public LoginAuthenticationFilter loginAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        LoginAuthenticationFilter loginFilter = new LoginAuthenticationFilter("/login");
        loginFilter.setAuthenticationManager(authenticationManager);
        loginFilter.setAuthenticationSuccessHandler(loginSuccessHandler);
        loginFilter.setAuthenticationFailureHandler(new AuthenticationEntryPointFailureHandler(authenticationFailureEntryPoint));
        return loginFilter;
    }

    public JwtAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        List<String> skipPaths = new ArrayList<>();
        skipPaths.addAll(JWT_AUTH_WHITELIST_SWAGGER);
        skipPaths.addAll(JWT_AUTH_WHITELIST_DEFAULT);
        FilterSkipMatcher matcher = new FilterSkipMatcher(skipPaths);

        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(matcher);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager);
        jwtAuthenticationFilter.setAuthenticationFailureHandler(new AuthenticationEntryPointFailureHandler(authenticationFailureEntryPoint));
        return jwtAuthenticationFilter;
    }

    @Bean
    public AuthenticationManager configureAuthenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(loginAuthenticationProvider);
        authenticationManagerBuilder.authenticationProvider(jwtAuthenticationProvider);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public SecurityFilterChain configure(AuthenticationManager authenticationManager, HttpSecurity http) throws Exception {

        http
                .httpBasic().disable()
                .formLogin().disable()
                .cors().disable()
                .csrf().disable()
                .headers().frameOptions().disable()

                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler)

                .and()
                .addFilterBefore(loginAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)

                .oauth2Login()
                .redirectionEndpoint().baseUri("/oauth2/login/callback/*")
                .and().userInfoEndpoint().userService(oAuth2UserService)
                .and().successHandler(oAuth2LoginSuccessHandler);

        return http.build();
    }

}

