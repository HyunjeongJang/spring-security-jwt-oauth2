package com.web.security.security.entity;

import com.web.security.domain.entity.Member;
import com.web.security.domain.type.MemberRole;
import com.web.security.security.exception.InvalidPasswordException;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;
import java.util.List;

@Getter
public class MemberSecurityEntity implements UserDetails {

    private final long memberId;

    private final String password;

    private final List<MemberRole> roles;

    public MemberSecurityEntity(Member member) {
        this.memberId = member.getId();
        this.password = member.getPassword();
        this.roles = List.of(member.getRole());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return String.valueOf(memberId);
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public String getRoleName() {
        return this.roles.stream()
                .findFirst()
                .map(Enum::name)
                .orElse("ANONYMOUS");
    }

    public void validatePassword(PasswordEncoder passwordEncoder, String password) {
        if(!passwordEncoder.matches(password, this.password)) {
            throw new InvalidPasswordException();
        }
    }
}
