package com.web.security.endpoint.member.service;

import com.web.security.domain.entity.Member;
import com.web.security.domain.repository.BlackListRedisRepository;
import com.web.security.domain.repository.MemberRepository;
import com.web.security.domain.repository.OAuth2AccountRepository;
import com.web.security.domain.repository.RefreshTokenRedisRepository;
import com.web.security.endpoint.member.dto.AdditionalInfoRequest;
import com.web.security.endpoint.member.dto.RegisterRequest;
import com.web.security.exception.EmailDuplicationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final BlackListRedisRepository blackListRedisRepository;
    private final RefreshTokenRedisRepository refreshTokenRedisRepository;

    @Transactional
    public void register(RegisterRequest request) {
        if (memberRepository.existsByEmail(request.getEmail())) {
            throw new EmailDuplicationException();
        }
        if (!request.getPassword().isBlank()) {
            request.encryptPassword(passwordEncoder);
        }
        Member member = Member.of(request);
        memberRepository.save(member);
    }

    @Transactional
    public void registerAdditionalInfo(long memberId, AdditionalInfoRequest request) {
        Member member = memberRepository.findById(memberId).orElseThrow();
        request.encryptPassword(passwordEncoder);
        member.changeAdditionalInfo(request);
        memberRepository.save(member);
    }

    @Transactional
    public void logout(long memberId, String accessToken) {
        blackListRedisRepository.set(accessToken);
        refreshTokenRedisRepository.delete(String.valueOf(memberId));
    }

    @Transactional
    public void delete(long memberId, String accessToken) {
        this.logout(memberId, accessToken);
        oAuth2AccountRepository.deleteAllByMemberId(memberId);
        memberRepository.deleteById(memberId);
    }

}
