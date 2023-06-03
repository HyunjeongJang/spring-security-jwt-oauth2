package com.web.security.endpoint.jwtauth;

import com.web.security.common.helper.JwtHelper;
import com.web.security.domain.type.MemberRole;
import com.web.security.endpoint.jwtauth.dto.ReIssueTokenCommand;
import com.web.security.endpoint.jwtauth.dto.ReIssueTokenRequest;
import com.web.security.endpoint.jwtauth.dto.ReIssueTokenResponse;
import com.web.security.endpoint.jwtauth.service.JwtAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/jwt/auth")
public class JwtAuthController {

    // 토큰 재발급 경우의수
    // 1. Access Token 을 재발급 받을 때 Refresh Token 을 새로 재발급
    // 2. Refresh Token 은 재발급 하지 않고 Access Token 만 재발급 받아서 Refresh Token 이 만료되면 로그아웃
    // Refresh Token 은 재발급 하지 않고 Access Token 만 새롭게 만듦

    private final JwtAuthService jwtAuthService;

    private final JwtHelper jwtHelper;

    // POST /jwt/auth/access-token 의 목표 : 재발급 (accessToken 이 만료됐으니까 refreshToken 을 가지고 재발급 해줌)
    // 1. AccessToken 이 만료됐다 -> 그래서 이걸 다시 발급받아야함
    // 2. RefreshToken 을 가지고 AccessToken 을 재발급해줌
    // 3. 반드시 사용자로부터 RefreshToken 을 받아야 함
    // 4. 성공하면 AccessToken 을 내림.

    // AccessToken 은 다른 API 를 호출할때 헤더에 넣어서 인증하기 위한 수단.
    // AccessToken 이 만료됐음을 깨달아야 함. -> 그럼 재발급 API 를 호출한다. // FE 에서 호출되는 시점? 토큰이 만료됐음을 깨달았을 때
    //  방법1) 일단 다른 API 를 호출 -> 401에러가 난다? -> 만료됐구나 -> 재발급 -> 다시 다른 API 호출
    //  방법2) 다른 API 를 호출하기전에 항상 AccessToken 만료기간을 체크  -> 만료됐어? -> 재발급 -> 그리고나서 다른 API 호출
    @PostMapping("/access-token")
    public ResponseEntity<ReIssueTokenResponse> reIssueAccessToken(@RequestHeader("Authorization") String accessTokenHeader,
                                                                   @RequestBody ReIssueTokenRequest request

    ) {
        // afterOf 토큰에 들어있는 role 꺼내기
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String accessToken = accessTokenHeader.substring("Bearer ".length());
        long memberId = Long.parseLong(jwtHelper.extractSubject(accessToken));
        MemberRole role = MemberRole.valueOf(jwtHelper.extractRole(accessToken));

        ReIssueTokenCommand command = new ReIssueTokenCommand(memberId, role, request.getRefreshToken());
        String reIssueAccessToken = jwtAuthService.reIssueAccessToken(command);
        return ResponseEntity.ok(new ReIssueTokenResponse(reIssueAccessToken, request.getRefreshToken()));
    }

    @GetMapping("/test/expired/accessToken")
    public ResponseEntity<Void> test(@AuthenticationPrincipal long memberId) {
        System.out.println("로그인한 사용자 : " + memberId);
        return ResponseEntity.ok().build();
    }


    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/test/expired/refreshToken")
    public ResponseEntity<Void> expiredToken(@AuthenticationPrincipal long memberId) {
        System.out.println("로그인한 사용자 : " + memberId);
        return ResponseEntity.ok().build();
    }

    // 403 에러 AccessDenied 에러 ->

}

