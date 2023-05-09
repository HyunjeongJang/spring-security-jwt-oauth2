package com.web.security.endpoint.login.service;

import com.web.security.domain.entity.Member;
import com.web.security.domain.repository.MemberRepository;
import com.web.security.endpoint.login.dto.MemberSecurityEntity;
import com.web.security.exception.EmailNotFoundException;
import com.web.security.exception.InvalidPasswordException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberSecurityService implements UserDetailsService {

    private final MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;

    public UserDetails validate(String email, String password) {
        Member member = memberRepository.findByEmail(email).orElseThrow(EmailNotFoundException::new);
        if(!member.validatePassword(passwordEncoder, password)) {
            throw new InvalidPasswordException();
        }
        return new MemberSecurityEntity(member);
    }

    @Override
    public UserDetails loadUserByUsername(String email) {
        return null;
    }
}
