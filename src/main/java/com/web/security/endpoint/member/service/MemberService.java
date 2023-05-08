package com.web.security.endpoint.member.service;

import com.web.security.domain.entity.Member;
import com.web.security.domain.repository.MemberRepository;
import com.web.security.endpoint.member.dto.RegisterRequest;
import com.web.security.exception.EmailDuplicationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;

    public void register(RegisterRequest req) {
        // 이미 존재하는 이메일인지 확인
        if(memberRepository.existsByEmail(req.getEmail())) {
            throw new EmailDuplicationException();
        }

        String encryptedPassword = passwordEncoder.encode(req.getPassword());
        Member member = Member.from(req, encryptedPassword);
        memberRepository.save(member);
    }
}
