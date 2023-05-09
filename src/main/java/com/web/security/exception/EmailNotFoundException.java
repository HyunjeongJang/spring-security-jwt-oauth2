package com.web.security.exception;

import org.springframework.security.core.AuthenticationException;

public class EmailNotFoundException extends AuthenticationException {

    public EmailNotFoundException() {
        this("잘못된 이메일 입니다.");
    }

    public EmailNotFoundException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public EmailNotFoundException(String msg) {
        super(msg);
    }
}
