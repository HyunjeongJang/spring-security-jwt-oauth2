package com.web.security.endpoint.jwtauth;

import com.web.security.security.exception.NotFoundAccessTokenException;
import com.web.security.endpoint.jwtauth.dto.JwtAuthentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String AUTHORIZATION_HEADER_PREFIX = "Bearer "; // JWT 토큰이란걸 명시적으로 작성

    public JwtAuthenticationFilter(RequestMatcher requestMatcher) {
        super(requestMatcher);
    }

    // 요청은 HttpServletRequest request 에 들어있고
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // FE 에서 어떻게 AccessToken 을 넘겨주는지에 따라 다름
        // 보통은 Request Header 를 통해서 넘겨주는걸로 가정하고, 그 Header 의 이름은 Authorization
        // Authorization: Bearer ~~ 형태

        // 사용자로부터 accessToken 을 받은걸 꺼내는 과정
        String accessToken = Optional.ofNullable(request.getHeader("Authorization"))
                .map(header -> header.substring(AUTHORIZATION_HEADER_PREFIX.length()))
                .orElseThrow(NotFoundAccessTokenException::new); // 토큰이 없으면 에러발생
        // Filter 안에서 AuthenticationException 이 발생하면 해당 Filter 에 등록된 FailureHandler 로 넘어감
        // 해당 객체 자체에 등록된 핸들러 authenticationFailureEntryPoint

        // 토큰 인증과 로그인은 전혀 관련이 없는 작업
        // 로그인 성공했을 때 토큰을 내리고 컨텍스트가 이어진다는것만 있음
        // 로그인을 시도했을땐 이 필터를 들어오면 안되는 것 -> config 에서 제외시켜줌 토큰 인증 필터를 타지 않도록

        // 인증 객체를 만듦
        JwtAuthentication before = JwtAuthentication.beforeOf(accessToken); // 인증객체에 accessToken 을 담아서
        AuthenticationManager manager = super.getAuthenticationManager();
        return super.getAuthenticationManager().authenticate(before); // Authentication(인증 전 객체) 객체를 넘겨서 AuthenticationManager 를 통해 인증 요청을 보냄
        // AuthenticationManager 는 인증할 수 있는 Provider 를 찾아서 위임
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        // Authentication authResult 에 멤버아이디랑 롤을 넣어서 반환한 객체가 들어있고
        JwtAuthentication afterOf = (JwtAuthentication) authResult;

        // SecurityContext 는 인증 객체가 저장되어 있는 공간
        // SecurityContextHolder 는 SecurityContext 에 전역적으로 접근할 수 있도록 해주는 객체
        SecurityContextHolder.clearContext(); // SecurityContextHolder 에 객체를 넣어서
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(afterOf);
        // SecurityContext 에 로그인 성공한 afterOf Token 을 넣어둠, 어디서든 꺼낼 수 있음(role 이 들어있음)
        SecurityContextHolder.setContext(context);

        chain.doFilter(request, response); // 성공했으면 끝이 아니라 통과이기 때문에 doFilter , 통과하면 컨트롤러로, 실패하면 AuthenticationFailureEntryPoint 로
    }

}

// Filter Chain
//  -> Filter 라는거는 Spring Application 으로 들어오는 HTTP Request 에 대해서 AOP 를 구현하고 싶은것
// 하나의 필터가 성공되면 다음으로. .다음.. 스킵. .다음
// 필터체인을 전부 통과하면 디스패쳐서블릿으로
// 성공하면 두필터 다음으로 진행시켜,
//로그인에선 성공하면 사용자에게 응답을 내리므로 필요없음


// Client -> 관문(JWT Authentication Filter) -> Controller(Handler) -> Service
//  <- 관문(JWT Authentication Filter) <-
// Tomcat 은 Request per Single Thread 방식으로 동작
// -> SecurityContext 안에는 ThreadLocal 이라는 변수를 통해서 인증 후 객체를 저장해둔다.