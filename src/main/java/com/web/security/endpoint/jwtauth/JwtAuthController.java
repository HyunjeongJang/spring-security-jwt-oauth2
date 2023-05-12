package com.web.security.endpoint.jwtauth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/jwt/auth")
public class JwtAuthController {

    @PostMapping("/access-token")
    public ResponseEntity<Void> reIsuueAccessToken(@AuthenticationPrincipal long memberId) {
        log.info("로그인된 사용자 ID : " + memberId);
        return ResponseEntity.ok().build();
    }
}

// 로그인 성공시 -> AccessToken, RefreshToken 을 반환 했고,
// 다른 요청이 올 때 AccessToken 이 잘 포함되어 있는지 확인해서
// 다른 요청이 올 떄 거칠 Filter (JwtAccessToken 인증을 하기 위한 필터)가 추가돼야함

