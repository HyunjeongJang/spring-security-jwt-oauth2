package com.web.security.exception;

public enum ErrorCode {

    INTERNAL_SERVER_ERROR("예상하지 못한 에러가 발생 했습니다."),
    EMAIL_DUPLICATION("중복된 이메일 입니다.");

    private String message;

    ErrorCode(String message) {
        this.message = message;
    }

    public String getMessage() {
        return this.message;
    }
}
