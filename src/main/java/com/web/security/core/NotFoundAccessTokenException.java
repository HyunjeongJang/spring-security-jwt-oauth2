package com.web.security.core;

import org.springframework.security.core.AuthenticationException;

public class NotFoundAccessTokenException extends AuthenticationException {

    public NotFoundAccessTokenException() {
        this("사용자의 AccessToken 을 찾을 수 없습니다.");
    }

    public NotFoundAccessTokenException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public NotFoundAccessTokenException(String msg) {
        super(msg);
    }
}
