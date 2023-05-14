package com.web.security.common.config;

import com.web.security.endpoint.login.LoginAuthenticationFilter;
import com.web.security.endpoint.login.LoginAuthenticationProvider;
import com.web.security.endpoint.jwtauth.JwtAuthenticationFilter;
import com.web.security.endpoint.jwtauth.JwtAuthenticationProvider;
import com.web.security.common.matcher.FilterSkipMatcher;
import com.web.security.endpoint.oauth2.service.MyOauth2UserService;
import com.web.security.security.handler.AuthenticationFailureEntryPoint;
import com.web.security.security.handler.LoginSuccessHandler;
import com.web.security.security.handler.OAuth2LoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 예외로 처리해줘야 할 것들 -> 토큰인증 없이 호출할 수 있어야 할 url 지정
    private static final List<String> JWT_AUTH_WHITELIST_SWAGGER = List.of("/v2/api-docs", "/configuration/ui", "/swagger-resources/**",
            "/configuration/security", "/swagger-ui.html/**", "/swagger-ui/**", "/webjars/**", "/swagger/**");

    private static final List<String> JWT_AUTH_WHITELIST_DEFAULT = List.of("/member/register", "/error", "/login", "/oauth2/**");

    private final LoginSuccessHandler loginSuccessHandler;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final AuthenticationFailureEntryPoint authenticationFailureEntryPoint;
    private final LoginAuthenticationProvider loginAuthenticationProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final MyOauth2UserService oAuth2UserService;

    public LoginAuthenticationFilter loginAuthenticationFilter() throws Exception {
        LoginAuthenticationFilter loginAuthenticationFilter = new LoginAuthenticationFilter("/login"); // 로그인 필터를 타는 대상
        loginAuthenticationFilter.setAuthenticationManager(super.authenticationManager());
        loginAuthenticationFilter.setAuthenticationSuccessHandler(loginSuccessHandler);
        loginAuthenticationFilter.setAuthenticationFailureHandler(new AuthenticationEntryPointFailureHandler(authenticationFailureEntryPoint));
        return loginAuthenticationFilter;
    }

    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        List<String> skipPaths = new ArrayList<>();
        skipPaths.addAll(JWT_AUTH_WHITELIST_SWAGGER);
        skipPaths.addAll(JWT_AUTH_WHITELIST_DEFAULT);
        FilterSkipMatcher matcher = new FilterSkipMatcher(skipPaths);

        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(matcher); // url 이 하나가 아니까 떄문에 request matcher 를 통해 지정
        jwtAuthenticationFilter.setAuthenticationManager(super.authenticationManager());
        jwtAuthenticationFilter.setAuthenticationFailureHandler(new AuthenticationEntryPointFailureHandler(authenticationFailureEntryPoint));
        return jwtAuthenticationFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(loginAuthenticationProvider);
        auth.authenticationProvider(jwtAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .httpBasic().disable() // HTTP 기반 인증
                .formLogin().disable()
                .cors().disable() // CORS -> Origin 문제
                .csrf().disable() // Rest API 서버는 stateless 하여 서버에 인증 정보를 보관x, jwt 토큰을 Cookie 에 저장하지 않는다면 csrf 공격에 어느 정도 안전하여 disable
                .headers().frameOptions().disable()

                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .exceptionHandling()

                .and()
                .addFilterBefore(loginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                .oauth2Login()
                .redirectionEndpoint().baseUri("/oauth2/login/callback/*")
                .and().userInfoEndpoint().userService(oAuth2UserService) // kakao 쪽 api 호출하는건 oauthClient 스프링 시큐리티 라이브러리를 이용
                .and().successHandler(oAuth2LoginSuccessHandler); // 성공시
    }

}
