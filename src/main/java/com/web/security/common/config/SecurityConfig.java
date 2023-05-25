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

    // 예외로 처리해줘야 할 것들 -> 토큰인증 없이 호출할 수 있어야 할 url 지정
    private static final List<String> JWT_AUTH_WHITELIST_SWAGGER = List.of("/v2/api-docs", "/configuration/ui", "/swagger-resources/**",
            "/configuration/security", "/swagger-ui.html/**", "/swagger-ui/**", "/webjars/**", "/swagger/**");
    private static final List<String> JWT_AUTH_WHITELIST_DEFAULT = List.of("/member/register", "/error", "/login", "/oauth2/**");

    private final MyOAuth2UserService oAuth2UserService;
    private final LoginSuccessHandler loginSuccessHandler;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final AuthenticationFailureEntryPoint authenticationFailureEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final LoginAuthenticationProvider loginAuthenticationProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    // Spring 에 Interceptor, Filter 를 등록할 때도 다 동일함
    // Interceptor, Filter 는 AOP 방식의 프로그래밍을할 때 쓸 수 있도록 Spring 에서 만들어준 도구
    // 제약사항 : Interceptor, Filter 는 HTTP Request 에 대해서만 AOP 를 구현할 수 있음
    // 항상 요청은 인터셉터와 필터를 거쳐갈 수 있는 가능성이 있음 (따라서 경로를 설정해야)
    public LoginAuthenticationFilter loginAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        // 로그인 필터 같은 경우는 /login 만 가능하도록 설정 이 경로로 왔을때만 필터를 타도록
        LoginAuthenticationFilter loginFilter = new LoginAuthenticationFilter("/login");
        loginFilter.setAuthenticationManager(authenticationManager);
        loginFilter.setAuthenticationSuccessHandler(loginSuccessHandler);
        loginFilter.setAuthenticationFailureHandler(new AuthenticationEntryPointFailureHandler(authenticationFailureEntryPoint));
        return loginFilter;
    }

    // 생성자가 들어가야 하는데 로그인 같은 경우에는 경로가 하나니까 String 으로 받았는데
    // jwt url 을 거쳐야 하는 url 은 무수히 많기 때문에 requestMatcher 라는걸 통해서 해당 요청이 필터를 타야하는지 안타야 하는지 검증해줌
    public JwtAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        List<String> skipPaths = new ArrayList<>();
        skipPaths.addAll(JWT_AUTH_WHITELIST_SWAGGER);
        skipPaths.addAll(JWT_AUTH_WHITELIST_DEFAULT);
        FilterSkipMatcher matcher = new FilterSkipMatcher(skipPaths);

        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(matcher); // 이 필터를 스킵해는 경로들을 넣어줌
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

    // 필터에서 인증 전 객체를 만들 때 인증할 수 있는 프로바이더한테 인증 해줘 라고 할때 authenticationManager 한테 요청하는데
    // 매니저는 프로바이더들에 대한 정보를 가지고 있어야 하므로 프로바이더 정보를 등록해 줌 // 없어도 됨
//    @Bean
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(loginAuthenticationProvider);
//        auth.authenticationProvider(jwtAuthenticationProvider);
//    }

    @Bean
    public SecurityFilterChain configure(AuthenticationManager authenticationManager, HttpSecurity http) throws Exception {
        http
                .httpBasic().disable() // HTTP 기반 인증
                .formLogin().disable()
                .cors().disable() // CORS -> Origin 문제
                .csrf().disable() // Rest API 서버는 stateless 하여 서버에 인증 정보를 보관x
                .headers().frameOptions().disable()

                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Jwt token 으로 인증하므로 STATELESS

                .and()
                .exceptionHandling()
                // .accessDeniedHandler(accessDeniedHandler)

                .and()
                .addFilterBefore(loginAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)

                .oauth2Login()
                .redirectionEndpoint().baseUri("/oauth2/login/callback/*")
                .and().userInfoEndpoint().userService(oAuth2UserService) // kakao 쪽 api 호출하는건 oauthClient 스프링 시큐리티 라이브러리를 이용
                .and().successHandler(oAuth2LoginSuccessHandler); // 성공시

        return http.build();
    }
}

