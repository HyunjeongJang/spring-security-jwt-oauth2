package com.web.security.endpoint.member.service;

import com.web.security.domain.entity.Member;
import com.web.security.domain.repository.MemberRepository;
import com.web.security.endpoint.member.dto.RegisterRequest;
import com.web.security.exception.EmailDuplicationException;
import com.web.security.exception.EmailNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void register(RegisterRequest request) {
        // 이미 존재하는 이메일인지 확인
        if(memberRepository.existsByEmail(request.getEmail())) {
            throw new EmailDuplicationException();
        }

        String encryptedPassword = passwordEncoder.encode(request.getPassword());
        Member member = Member.of(request, encryptedPassword);
        memberRepository.save(member);
    }

    public Member find(String email) {
        return memberRepository.findByEmail(email).orElseThrow(EmailNotFoundException::new);
    }
}
