package com.web.security.endpoint.member.service;

import com.web.security.domain.repository.MemberRepository;
import com.web.security.endpoint.member.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    public void register(RegisterRequest req) {

    }
}
