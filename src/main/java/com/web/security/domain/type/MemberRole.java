package com.web.security.domain.type;

import org.springframework.security.core.GrantedAuthority;

public enum MemberRole implements GrantedAuthority {

    GENERAL, ADMIN;

    @Override
    public String getAuthority() {
        return this.name();
    }

}
