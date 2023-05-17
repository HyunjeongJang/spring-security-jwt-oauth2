package com.web.security.endpoint.member;

import com.web.security.endpoint.member.dto.RegisterRequest;
import com.web.security.endpoint.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {

    private static final String AUTHORIZATION_HEADER_PREFIX = "Bearer ";
    private final MemberService memberService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody RegisterRequest request) {
        memberService.register(request);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader(name = "Authorization") String authorization,
            @AuthenticationPrincipal long memberId
    ) {
        String accessToken = authorization.substring(AUTHORIZATION_HEADER_PREFIX.length());
        memberService.logout(memberId, accessToken);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> delete(
            @RequestHeader(name = "Authorization") String authorization,
            @AuthenticationPrincipal long memberId
    ) {
        String accessToken = authorization.substring(AUTHORIZATION_HEADER_PREFIX.length());
        memberService.delete(memberId, accessToken);
        return ResponseEntity.ok().build();
    }

}
