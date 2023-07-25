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
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/jwt/auth")
public class JwtAuthController {

    private final JwtAuthService jwtAuthService;
    private final JwtHelper jwtHelper;

    @PostMapping("/access-token")
    public ResponseEntity<ReIssueTokenResponse> reIssueAccessToken(
            @RequestHeader("Authorization") String accessTokenHeader,
            @RequestBody ReIssueTokenRequest request

    ) {
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

}

