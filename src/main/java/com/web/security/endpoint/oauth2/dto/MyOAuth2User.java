package com.web.security.endpoint.oauth2.dto;

import com.web.security.domain.entity.OAuth2Account;
import com.web.security.domain.type.MemberRole;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
public class MyOAuth2User implements OAuth2User {

    private final long memberId;
    private final String accountId;
    private final MemberRole role;
    private final boolean isEnabled;

    public MyOAuth2User (OAuth2Account savedAccount) {
        this.memberId = savedAccount.getMember().getId();
        this.accountId = savedAccount.getAccountId();
        this.role = savedAccount.getMember().getRole();
        this.isEnabled = savedAccount.getMember().isEnabled();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return new HashMap<>();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(role);
    }

    @Override
    public String getName() {
        return this.accountId;
    }

    public long getMemberId() {
        return this.memberId;
    }
}
