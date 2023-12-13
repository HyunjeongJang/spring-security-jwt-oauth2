# spring-security-jwt-oauth2 ver.01
<!--
## 스프링 시큐리티 흐름
<image src="https://github.com/HyunjeongJang/spring-security-jwt-oauth2/assets/113197284/3226523a-713d-4872-acc6-9579dca210e7" width="800">

1. Filter 에서 HttpRequest 요청을 받아 Provider 에게 인증 전 객체를 주면서 인증요청을 보내야 한다.
**AuthenticationFilter** 에서 인증 전 객체를 만들어 냄

2. **UsernamePasswordAuthenticationToken**
Authentication 이라는 interface 를 구현한 구현체
Token 개념이 아니라 Authentication 객체이다. (인증 전 객체, 인증 후 객체)

3. **AuthenticationManager** 
인증은 여러가지의 인증이 있을 수 있는데 Provider는 하나의 인증객체만 처리가 가능하므로 내가 가진 인증 객체를 처리할 수 있는 적절한 Provider를 선택해주는 것

4. **AuthenticationProvider** 실질적으로 인증에 대한 비지니스 로직을 갖는다.
성공시 : return 인증 후 객체
실패시 : AuthenticationException 에러를 던짐. 그래야 Spring Security 내부적으로 에러처리가 가능(RuntimeException은 Security 에서 인식을 하지 못함)

5. **UserDetails / UserDetailService**
로그인 요청이므로 Provider가 어떤 인증인지 처리할 때 필요한것을 호출해서 사용한다.

9. 다시 Filter 로 돌아와 성공시 SuccessHandler / 실패시 FailureHandler 로 보내진다.

10. **SecurityContextHolder**
SecurityContext 는 인증 객체가 저장되어 있는 공간
SecurityContextHolder 는 SecurityContext 에 전역적으로 접근할 수 있도록 해주는 객체이다.

-->

# **개발환경**
Java 11\
Spring Boot 2.7.12\
MySQL\
JPA

# **설정**
기본 회원 - Jwt 토큰 인증 기반\
OAuth2.0 카카오 로그인\
기본회원 - 카카오 로그인 연동 (이메일 필수, 비밀번호 추가 입력시 카카오 로그인 회원도 일반회원처럼 로그인 가능하도록 하였음)\
소셜로그인 연결끊기(토큰인증 처리)



# Spring Security Login

## 0. Config
**SecurityConfig**
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

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
```

## 1. Filter
```java
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
```

## 1.5 Authentication 객체
```java
public class LoginAuthentication extends UsernamePasswordAuthenticationToken {

    public LoginAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public LoginAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public static LoginAuthentication beforeOf(LoginRequest req) {
        return new LoginAuthentication(req.getEmail(), req.getPassword());
    }

    public static Authentication afterOf(String accessToken, String refreshToken) {
        JwtDto jwtDto = new JwtDto(accessToken, refreshToken);
        return new LoginAuthentication(jwtDto, "", List.of());
    }

    public String getEmail() {
        return (String) this.getPrincipal();
    }

    public String getPassword() {
        return (String) this.getCredentials();
    }

    public String getAccessToken() {
        return ((JwtDto) this.getPrincipal()).getAccessToken();
    }

    public String getRefreshToken() {
        return ((JwtDto) this.getPrincipal()).getRefreshToken();
    }

    @Data
    @AllArgsConstructor
    static class JwtDto {
        private String accessToken;
        private String refreshToken;
    }
}
```

## 2. Provider
```java
@Component
@RequiredArgsConstructor
public class LoginAuthenticationProvider implements AuthenticationProvider {

    private final MemberSecurityService memberSecurityService;
    private final JwtHelper jwtHelper;
    private final RefreshTokenRedisService refreshTokenRedisService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginAuthentication before = (LoginAuthentication) authentication;
        MemberSecurityEntity user = (MemberSecurityEntity) memberSecurityService.loadUserByUsername(before.getEmail());
        user.validatePassword(passwordEncoder, before.getPassword());
        String accessToken = jwtHelper.generateAccessToken(user.getUsername(), user.getRoleName());
        String refreshToken = jwtHelper.generateRefreshToken(user.getUsername());
        refreshTokenRedisService.save(refreshToken);
        return LoginAuthentication.afterOf(accessToken, refreshToken); 
    }

    @Override
    public boolean supports(Class<?> authentication) { 
        return LoginAuthentication.class.isAssignableFrom(authentication);
    }
}
```


## 회원 등록

**Member Entity**

```java
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Getter
public class Member extends AbstractAggregateRoot {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    private String email;

    private String password;

    private String nickname;

    @Enumerated(EnumType.STRING)
    private MemberRole role;

    @Column(name = "enabled_yn")
    private boolean enabled;

    public static Member of(RegisterRequest request) {
        return Member.builder()
                .email(request.getEmail())
                .password(request.getPassword())
                .nickname(request.getNickname())
                .role(MemberRole.GENERAL)
                .enabled(!request.getPassword().isBlank())
                .build();
    }

    public void changeAdditionalInfo(AdditionalInfoRequest request) {
        this.password = request.getPassword();
        this.enabled = true;
    }
}

```

**MemberRole**

```java
public enum MemberRole implements GrantedAuthority {
    GENERAL, ADMIN;

    @Override
    public String getAuthority() {
        return this.name();
    }
}
```

**PasswordEncoder**
```java
@Configuration
public class PasswordEncodingConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

**MemberService**
```java
@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void register(RegisterRequest request) {
    	// 이미 존재하는 이메일인지 확인
        if (memberRepository.existsByEmail(request.getEmail())) {
            throw new EmailDuplicationException();
        }
        if (!request.getPassword().isBlank()) {
            request.encryptPassword(passwordEncoder);
        }
        Member member = Member.of(request);
        memberRepository.save(member);
    }
}
```



**MemberController**
```java
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody RegisterRequest requset) {
        memberService.register(requset);
        return ResponseEntity.ok().build();
    }

}
```

## Exception
**GlobalExceptionHandler** 
전역적으로 사용할 ExceptionHandler 설정

```java
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(EmailDuplicationException.class)
    public ResponseEntity<ErrorResponse> emailDuplicationExceptionHandler(EmailDuplicationException ex) {
        log.error(ex.getMessage(), ex);
        ErrorResponse resp = ErrorResponse.from(ex.getErrorCode());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(resp);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ErrorResponse> runtimeExceptionHandler(RuntimeException ex) {
        log.error(ex.getMessage(), ex);
        return ResponseEntity.internalServerError().body(ErrorResponse.from(ErrorCode.INTERNAL_SERVER_ERROR));
    }
}
```


# JWT
## 1. Filter

```java
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String AUTHORIZATION_HEADER_PREFIX = "Bearer "; // JWT 토큰이란걸 명시적으로 작성

    public JwtAuthenticationFilter(RequestMatcher requestMatcher) {
        super(requestMatcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String accessToken = Optional.ofNullable(request.getHeader("Authorization"))
                .map(header -> header.substring(AUTHORIZATION_HEADER_PREFIX.length()))
                .orElseThrow(NotFoundAccessTokenException::new); 
        JwtAuthentication before = JwtAuthentication.beforeOf(accessToken); 
        return super.getAuthenticationManager().authenticate(before); 
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        JwtAuthentication afterOf = (JwtAuthentication) authResult;
        SecurityContextHolder.clearContext(); 
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(afterOf);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response); 
    }
}
```

## 1.5 AuthenticationToken
```java
public class JwtAuthentication extends UsernamePasswordAuthenticationToken {
    public JwtAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public JwtAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public static JwtAuthentication beforeOf(String accessToken) {
        return new JwtAuthentication(accessToken, "");
    }

    public static Authentication afterOf(long memberId, MemberRole role) {
        return new JwtAuthentication(memberId, "", List.of(role));
    }

    public String getAccessToken() {
        return (String) this.getPrincipal();
    }
}
```

## 2. Provider
```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtHelper jwtHelper;
    private final BlackListRedisRepository blackListRedisRepository;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthentication before = (JwtAuthentication) authentication; 
        
        String accessToken = before.getAccessToken();
        if (blackListRedisRepository.exists(accessToken)) {
            throw new BlackListedAccessTokenException(); 
        }
        if (!jwtHelper.validate(accessToken)) { 
            throw new InvalidAccessTokenException(); 
        }

        long memberId = Long.parseLong(jwtHelper.extractSubject(accessToken));
        MemberRole role = MemberRole.valueOf(jwtHelper.extractRole(accessToken));
        return JwtAuthentication.afterOf(memberId, role); 
    }

    @Override
    public boolean supports(Class<?> authentication) { 
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }
}
```

# OAuth

**Member**
* 일반로그인 기본 회원과 kakao 회원을 연동하기위해 kakao 로그인시 비밀번호 추가로 입력받아야 하는 조건을 위해 enabled_yn 칼럼 추가 
* 비밀번호 입력시 Y가 되며 일반 로그인으로도 이용 가능 해짐
```java
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Getter
public class Member extends AbstractAggregateRoot {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    private String email;

    private String password;

    private String nickname;

    @Enumerated(EnumType.STRING)
    private MemberRole role;

    @Column(name = "enabled_yn")
    private boolean enabled;

    public static Member of(RegisterRequest request) {
        return Member.builder()
                .email(request.getEmail())
                .password(request.getPassword())
                .nickname(request.getNickname())
                .role(MemberRole.GENERAL)
                .enabled(!request.getPassword().isBlank())
                .build();
    }
}
```

**BooleanToYNConverter**
Boolean 타입을 Y,N 값으로 넣기 위해 Converter 설정
```java
@Converter(autoApply = true)
public class BooleanToYNConverter implements AttributeConverter<Boolean, String> {
    @Override
    public String convertToDatabaseColumn(Boolean attribute) {
        return attribute ? "Y" : "N";
    }

    @Override
    public Boolean convertToEntityAttribute(String dbData) {
        return dbData.equals("Y");
    }
}
```


**OAuth2Account Entity**
```java
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Table(name = "oauth2_account")
public class OAuth2Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "oauth2_account_id")
    private Long id;

    private String providerName;
    private String accountId;

    @JoinColumn(name = "member_id", referencedColumnName = "member_id")
    @ManyToOne(fetch = FetchType.LAZY)
    private Member member;

    @Transient 
    private String email;

    @Transient
    private String nickname;

    public static OAuth2Account of(OAuth2UserRequest request, OAuth2User user) {
        String registrationId = request.getClientRegistration().getRegistrationId(); // kakao (yml - registration 부분)
        String attributeName = request.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        OAuth2Account oAuth2Account = null;
        if(registrationId.equals("kakao")) {
            oAuth2Account = OAuth2Account.ofKakao(user, registrationId, attributeName);
        }
        return oAuth2Account;
    }

    public static OAuth2Account ofKakao(OAuth2User user, String registrationId, String attributeName) {
        Map<String, Object> attributes = user.getAttributes();
        Map<String, Object> profile = (Map<String, Object>) attributes.get("properties");
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");

        String nickname = Optional.ofNullable((String) profile.get("nickname")).orElse("");
        String email = Optional.ofNullable((String) account.get("email")).orElse("");

        return OAuth2Account.builder()
                .providerName("KAKAO")
                .accountId(((Long) Objects.requireNonNull(user.getAttribute(attributeName))).toString())
                .email(email)
                .nickname(nickname)
                .build();
    }

    public void setMember(Member member) {
        this.member = member;
    }
}
```
### OAuth2User
**MyOAuth2User** - dto
```java
@Getter
public class MyOAuth2User implements OAuth2User {

    private final long memberId;
    private final String accountId;
    private final MemberRole role;
    private final boolean isEnabled;

    public MyOAuth2User (OAuth2Account savedAccount) {
        this.memberId = savedAccount.getMember().getId();
        this.accountId = savedAccount.getAccountId();
        this.role = savedAccount.getMember().getRole();
        this.isEnabled = savedAccount.getMember().isEnabled();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return new HashMap<>();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(role);
    }

    @Override
    public String getName() {
        return this.accountId;
    }

    public long getMemberId() {
        return this.memberId;
    }
}
```

**RegisterRequest**

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    private String email;
    private String password;
    private String nickname;

    public static RegisterRequest from(OAuth2Account account) {
        return new RegisterRequest(account.getEmail(), "", account.getNickname());
    }
}

```

**MemberResponse**
```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MemberResponse {

    private long memberId;
    private String email;
    private String password;
    private String nickname;
    private MemberRole role;

    public static MemberResponse from(Member member) {
        return new MemberResponse(
                member.getId(),
                member.getEmail(),
                member.getPassword(),
                member.getNickname(),
                member.getRole());
    }
}
```



### OAuth2UserService
**MyOauth2UserService**
```java
@Service
@RequiredArgsConstructor
public class MyOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final MemberRepository memberRepository;
    private final MemberService memberService;
    private final OAuth2AccountRepository oAuth2AccountRepository;

    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> userService = new DefaultOAuth2UserService();
        OAuth2User user = userService.loadUser(userRequest); 

        OAuth2Account oAuth2Account = OAuth2Account.of(userRequest, user);
        if(!memberRepository.existsByEmail(oAuth2Account.getEmail())) {
            memberService.register(RegisterRequest.from(oAuth2Account));
        }
        Member member = memberRepository.getByEmail(oAuth2Account.getEmail());
        oAuth2Account.setMember(member);
        if (!oAuth2AccountRepository.existsByProviderNameAndAccountId(oAuth2Account.getProviderName(), oAuth2Account.getAccountId())) {
            oAuth2AccountRepository.save(oAuth2Account);
        }
        return new MyOAuth2User(oAuth2Account);
    }
}
```

**MemberRepository**

```java
@Repository
public interface MemberRepository extends CrudRepository<Member, Long> {
    boolean existsByEmail(String email);
    Optional<Member> findByEmail(String email); 
    Member getByEmail(String email);
}
```
**OAuth2AccountRepository**
```java
@Repository
public interface OAuth2AccountRepository extends CrudRepository<OAuth2Account, Long> {
    boolean existsByProviderNameAndAccountId(String providerName, String accountId);
    OAuth2Account findByProviderNameAndAccountId(String providerName, String accountId);
}
```


**OAuth2LoginSuccessHandler**
```java
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtHelper jwtHelper;
    private final RefreshTokenRedisService refreshTokenRedisService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth) throws IOException, ServletException {

        MyOAuth2User user = (MyOAuth2User) auth.getPrincipal();
        String subject = String.valueOf(user.getMemberId());

        String accessToken = jwtHelper.generateAccessToken(subject, user.getRole().name());
        String refreshToken = jwtHelper.generateRefreshToken(subject);
        refreshTokenRedisService.save(refreshToken);

        LoginResponse loginResponse = new LoginResponse(accessToken, refreshToken, user.isEnabled());
        String body = new ObjectMapper().writeValueAsString(loginResponse);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().println(body);
    }

}

```

<!--

## 일반회원과 연동
kakao 가입시 해당 이메일로 일반회원 로그인도 가능하게 하기위해 비밀번호 입력을 하도록 설정

**AdditionalInfoRequest**
```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdditionalInfoRequest {

	private String password;

	public void encryptPassword(PasswordEncoder passwordEncoder) {
		this.password = passwordEncoder.encode(password);
	}
}
```

**LoginResponse**
isEnabled 추가
```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    private String accessToken;
    private String refreshToken;
    private boolean isEnabled;

    public LoginResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.isEnabled = true;
    }

}
```


**MemberService**
```java
@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRedisRepository refreshTokenRedisRepository;

    @Transactional
    public void registerAdditionalInfo(long memberId, AdditionalInfoRequest request) {
        Member member = memberRepository.findById(memberId).orElseThrow();
        request.encryptPassword(passwordEncoder);
        member.changeAdditionalInfo(request);
        memberRepository.save(member);
    }



```
**MemberController**
```java
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {

    private static final String AUTHORIZATION_HEADER_PREFIX = "Bearer ";
    private final MemberService memberService;
   
    @PutMapping("/additional-info")
    public ResponseEntity<Void> registerAdditionalInfo(
        @AuthenticationPrincipal long memberId,
        @RequestBody AdditionalInfoRequest request
    ) {
        memberService.registerAdditionalInfo(memberId, request);
        return ResponseEntity.ok().build();
    }

}

```
-->









