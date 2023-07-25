package com.web.security.exception;

import lombok.Getter;

@Getter
public class EmailDuplicationException extends BusinessException{

    private final ErrorCode errorCode;

    public EmailDuplicationException() {
        this(ErrorCode.EMAIL_DUPLICATION, ErrorCode.EMAIL_DUPLICATION.getMessage());
    }

    public EmailDuplicationException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

}
