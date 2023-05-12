package com.web.security.endpoint.login.dto;

import com.web.security.domain.entity.Member;
import com.web.security.domain.type.MemberRole;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
public class MemberSecurityEntity implements UserDetails {

    private final long memberId;

    private final List<MemberRole> roles;

    public MemberSecurityEntity() {
        this.memberId = 0;
        this.roles = List.of();
    }

    public MemberSecurityEntity(Member member) {
        this.memberId = member.getId();
        this.roles = List.of(member.getRole());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getPassword() {
        return "";
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
}
