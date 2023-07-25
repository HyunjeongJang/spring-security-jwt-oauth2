package com.web.security.security.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidAccessTokenException extends AuthenticationException {

    public InvalidAccessTokenException() {
        this("잘못된 AccessToken 입니다.");
    }

    public InvalidAccessTokenException(Throwable cause) { // 에러는 중첩이 될 수 있음
        this("잘못된 AccessToken 입니다..");
    }

    public InvalidAccessTokenException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public InvalidAccessTokenException(String msg) {
        super(msg);
    }

}
