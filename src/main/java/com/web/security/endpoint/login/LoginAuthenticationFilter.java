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
    // 사용자의 자격 증명 정보를 인증하는 기본 필터로 사용, AuthenticationEntryPoint 로 자격 증명 정보를 요청하고 나면, AbstractAuthenticationProcessingFilter 가 인증 요청을 수행

    public LoginAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    // 사용자가 HTTP(프로토콜) Request(정해진 포맷이 있음) 를 보내는것
    // 사용자가 요청을 보냈다 -> 요청에 대한 모든 데이터는 HttpServletRequest request 객체 안에 들어있음.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
             throws AuthenticationException, IOException {

//        // 요청 메서드 확인
//        if (!"POST".equals(request.getMethod())) {
//            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
//        }

        // Login 요청이니까 email, password 가 request 의 Body 안에 들어있다고 가정(보통 password 는 RequestBody 에 넣)
        // ObjectMapper (Jackson) : JSON > 객체 or 객체 > JSON (Mapping)
        LoginRequest loginRequest = new ObjectMapper().readValue(request.getReader(), LoginRequest.class);
        // getReader() 리퀘스트 바디에서 꺼내는 과정 / 데이터가 바이트 배열로 넘어옴 -> 객체가 필요하니까 ObjectMapper 로 객체로 바꾸는 과정
        // Authentication 객체 (인증 전 객체)
        LoginAuthentication before = LoginAuthentication.beforeOf(loginRequest);
        // loginRequest 객체는 POJO 형태인데 spring security 에 의존적인 Authentication 객체가 필요하므로 LoginAuthentication 에서 해당 형태로 만들어줌

        // 사용자가 준 정보로 인증 전 객체를 만들었고 그 객체를 인증할 수 있는 프로바이더에게 인증요청을 보내야 함 (AuthenticationManager 에게 부탁)

//        AuthenticationManager authenticationManager = super.getAuthenticationManager();
        return super.getAuthenticationManager().authenticate(before);
    }

    // 인증에 성공하면 다시 필터로 돌아오고
    // successfulHandler 주는 방법
    // 1) 필터 안에서 오버라이딩 해서 구현
    // 2) 별도 클래스 만들어서 객체 자체에 등록 (SecurityConfig loginAuthenticationFilter() setAuthenticationSucessHandler 에 등록돼있음

//    @Override
//    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
//                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
//        LoginAuthenticationToken afterToken = (LoginAuthenticationToken) authResult;
//        log.info("로그인 성공^^ AccessToken : " + afterToken.getAccessToken());
//        super.successfulAuthentication(request, response, chain, authResult);
//    }
}

//
//  OAuth 로그인으로 회원가입 & 로그인을 성공하면 서버는 FE 에게 AccessToken & RefreshToken 을 내려줌.
//   1. FE 에서 어떤 방식으로든 추가정보를 입력받는 화면으로 보내줘야함.
//      - 로그인 성공했을 때 응답에 isEnabled 필드를 추가해 이 값이 false 면 FE 에서 추가정보를 입력받는 화면으로 보내줘.
//   2. 확인버튼을 누르면 추가정보가 저장되는 API 호출.