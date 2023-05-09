package com.web.security.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidPasswordException extends AuthenticationException {

    public InvalidPasswordException() {
        this("패스워드가 일치하지 않습니다");
    }

    public InvalidPasswordException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public InvalidPasswordException(String msg) {
        super(msg);
    }
}
