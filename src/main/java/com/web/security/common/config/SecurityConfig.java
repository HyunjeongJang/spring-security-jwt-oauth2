package com.web.security.common.config;

import com.web.security.endpoint.login.LoginAuthenticationFilter;
import com.web.security.security.handler.LoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final LoginSuccessHandler loginSuccessHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public LoginAuthenticationFilter loginAuthenticationFilter() throws Exception {
        LoginAuthenticationFilter loginAuthenticationFilter = new LoginAuthenticationFilter("/login");
        loginAuthenticationFilter.setAuthenticationManager(super.authenticationManager());
        loginAuthenticationFilter.setAuthenticationSuccessHandler(loginSuccessHandler);
        return loginAuthenticationFilter;
    }

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
                .addFilterBefore(loginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

}
