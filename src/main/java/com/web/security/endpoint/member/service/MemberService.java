package com.web.security.endpoint.member.service;

import com.web.security.domain.entity.Member;
import com.web.security.domain.repository.MemberRepository;
import com.web.security.endpoint.member.dto.RegisterRequest;
import com.web.security.exception.EmailDuplicationException;
import com.web.security.security.exception.EmailNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityNotFoundException;

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
        if(!request.getPassword().isBlank()) {
            request.encryptPassword(passwordEncoder);
        }

//        String encryptedPassword = passwordEncoder.encode(request.getPassword());
//        Member member = Member.of(request, encryptedPassword);
        Member member = Member.of(request);
        memberRepository.save(member);
    }

//    public Member find(String email) {
//        return memberRepository.findByEmail(email).orElseThrow(EmailNotFoundException::new);
//    }

//    public boolean existsByEmail(String email) {
//        return memberRepository.existsByEmail(email);
//    }

//    public MemberResponse retrieve(String email) {
//        return memberRepository.findByEmail(email)
//                .map(MemberResponse::from)
//                .orElseThrow(() -> new EntityNotFoundException("해당 이메일을 가진 사용자를 찾을 수 없습니다."));
//    }
}
