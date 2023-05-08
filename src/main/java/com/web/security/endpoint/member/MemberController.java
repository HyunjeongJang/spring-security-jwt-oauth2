package com.web.security.endpoint.member;

import com.web.security.endpoint.member.dto.RegisterRequest;
import com.web.security.endpoint.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {

    private final MemberService memberService;

    @PostMapping
    public ResponseEntity<Void> register(@RequestBody RegisterRequest req) {
        memberService.register(req);
        return ResponseEntity.ok().build();
    }

}
