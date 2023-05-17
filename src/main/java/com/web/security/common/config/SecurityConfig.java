package com.web.security.common.config;

import com.web.security.endpoint.login.LoginAuthenticationFilter;
import com.web.security.endpoint.login.LoginAuthenticationProvider;
import com.web.security.endpoint.jwtauth.JwtAuthenticationFilter;
import com.web.security.endpoint.jwtauth.JwtAuthenticationProvider;
import com.web.security.common.matcher.FilterSkipMatcher;
import com.web.security.endpoint.oauth2.service.MyOAuth2UserService;
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

    private final MyOAuth2UserService oAuth2UserService;
    private final LoginSuccessHandler loginSuccessHandler;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final AuthenticationFailureEntryPoint authenticationFailureEntryPoint;
    private final LoginAuthenticationProvider loginAuthenticationProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    public LoginAuthenticationFilter loginAuthenticationFilter() throws Exception {
        LoginAuthenticationFilter loginFilter = new LoginAuthenticationFilter("/login");
        loginFilter.setAuthenticationManager(super.authenticationManager());
        loginFilter.setAuthenticationSuccessHandler(loginSuccessHandler);
        loginFilter.setAuthenticationFailureHandler(new AuthenticationEntryPointFailureHandler(authenticationFailureEntryPoint));
        return loginFilter;
    }

    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        List<String> skipPaths = new ArrayList<>();
        skipPaths.addAll(JWT_AUTH_WHITELIST_SWAGGER);
        skipPaths.addAll(JWT_AUTH_WHITELIST_DEFAULT);
        FilterSkipMatcher matcher = new FilterSkipMatcher(skipPaths);

        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(matcher);
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

// 로그인 -> AccessToken A & RefreshToken A 를 발급해서 내려줌
// 		   RefreshToken A 는 Redis 의 REFRESH_TOKEN:1 이라는 곳에 저장
// 로그아웃 -> REFRESH_TOKEN:1 에 저장된 RefreshToken A 를 지움 (RefreshToken A 로 언제든지 AccessToken N 을 새롭게 발급할 수 있으니까)
//          AccessToken A 를 BLACK_LIST 에 등록.
//          Client 가 가지고 있는 AccessToken A 로는 토큰인증을 통과할 수 없음
// 그리고 다시 로그인 -> AccessToken B & RefreshToken B 를 발급해서 내려줌
//                  AccessToken B 는 블랙리스트에 등록되어있지 않기 때문에 토큰인증을 통과할 수 있음

// 회원탈퇴 -> OAuth 는 기본 서비스랑 관련이 x
//    Member 테이블만 지워주면 탈퇴는 된거지만 카카오쪽에 연동이력이 남아있고, 재가입시에 약관이 뜨지 않음
//    -> AccessToken (카카오에서 만들어준 AccessToken) 이 필요함.
//    -> 저장 or 사용자가 다시 로그인 해야함
//    -> 카카오 로그인을 통해 회원가입을 했어도 일반 로그인으로 이용이 가능한데
//    -> 저장을 하면 생기는 문제
//        -> 탈퇴는 언제할지 모르고 영영 안할수도 있는데
//        -> AccessToken, RefreshToken 을 저장할 수는 있으나 만료기간이 있음
//        -> 엄청 나중에 회원탈퇴를 시도하면 AccessToken, RefreshToken 모두 만료된 상태일 것 -> 연결끊기 실패
//        -> 주기적으로 백그라운드에서 돌면서 RefreshToken 이 만료되기 전에 계속 AccessToken, RefreshToken 을 재발급 해야하는데 오버엔지니어링 같음
