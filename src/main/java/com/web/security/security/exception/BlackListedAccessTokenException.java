package com.web.security.security.exception;

import org.springframework.security.core.AuthenticationException;

public class BlackListedAccessTokenException extends AuthenticationException {
    public BlackListedAccessTokenException() {
        this("블랙리스트에 등록된 AccessToken 입니다.");
    }

    public BlackListedAccessTokenException(String msg) {
        super(msg);
    }
}

