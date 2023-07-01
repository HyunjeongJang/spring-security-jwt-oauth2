# spring-security-jwt-oauth2
<image src="https://github.com/HyunjeongJang/spring-security-jwt-oauth2/assets/113197284/3226523a-713d-4872-acc6-9579dca210e7" width="800">

>1. Filter 에서 HttpRequest 요청을 받아 Provider 에게 인증 전 객체를 주면서 인증요청을 보내야 한다.
**AuthenticationFilter** 에서 인증 전 객체를 만들어 냄
>
>
>2. **UsernamePasswordAuthenticationToken**
Authentication 이라는 interface 를 구현한 구현체
Token 개념이 아니라 Authentication 객체이다. (인증 전 객체, 인증 후 객체)
>
>
>3. **AuthenticationManager** 
인증은 여러가지의 인증이 있을 수 있는데 Provider는 하나의 인증객체만 처리가 가능하므로 내가 가진 인증 객체를 처리할 수 있는 적절한 Provider를 선택해주는 것
>
>
>4. **AuthenticationProvider** 실질적으로 인증에 대한 비지니스 로직을 갖는다.
성공시 : return 인증 후 객체
실패시 : AuthenticationException 에러를 던짐. 그래야 Spring Security 내부적으로 에러처리가 가능(RuntimeException은 Security 에서 인식을 하지 못함)
>
>
>5. **UserDetails / UserDetailService**
로그인 요청이므로 Provider가 어떤 인증인지 처리할 때 필요한것을 호출해서 사용한다.
>
>
>9. 다시 Filter 로 돌아와 성공시 SuccessHandler / 실패시 FailureHandler 로 보내진다.
>
>
>10. **SecurityContextHolder**
SecurityContext 는 인증 객체가 저장되어 있는 공간
SecurityContextHolder 는 SecurityContext 에 전역적으로 접근할 수 있도록 해주는 객체
