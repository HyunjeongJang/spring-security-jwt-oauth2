package com.web.security.endpoint.jwtauth;

import com.web.security.endpoint.jwtauth.dto.ReIssueTokenCommand;
import com.web.security.endpoint.jwtauth.dto.ReIssueTokenRequest;
import com.web.security.endpoint.jwtauth.dto.ReIssueTokenResponse;
import com.web.security.endpoint.jwtauth.service.JwtAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
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
    // 2. Refresh Token 은 재발급 하지 않고 Access Token 만 재발급 받아서 Refresh Token 이 만료되면 로그아웃 (보통의 경우)

    // Refresh Token 은 재발급 하지 않고 Access Token 만 새롭게 만듦
    private final JwtAuthService jwtAuthService;

    @PostMapping("/access-token")
    public ResponseEntity<ReIssueTokenResponse> reIssueAccessToken(@RequestBody ReIssueTokenRequest request
    ) {

        // afterOf 토큰에 들어있는 role 꺼내기
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        ReIssueTokenCommand command = new ReIssueTokenCommand(auth, request);
        String accessToken = jwtAuthService.reIssueAccessToken(command);
        return ResponseEntity.ok(new ReIssueTokenResponse(accessToken, request.getRefreshToken()));
    }

    @GetMapping("/test/expired/refreshToken")
    public ResponseEntity<Void> expiredToken(@AuthenticationPrincipal long memberId) {
        System.out.println("로그인한 사용자 : " + memberId);
        return ResponseEntity.ok().build();
    }
}

