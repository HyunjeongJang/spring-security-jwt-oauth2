package com.web.security.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(EmailDuplicationException.class)
    public ResponseEntity<ErrorResponse> emailDuplicationExceptionHandler(EmailDuplicationException ex) {
        log.error(ex.getMessage(), ex);
        ErrorResponse resp = ErrorResponse.from(ex.getErrorCode());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(resp);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> accessDeniedExceptionHandler(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ErrorResponse.from(ErrorCode.FORBIDDEN));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ErrorResponse> runtimeExceptionHandler(RuntimeException ex) {
        log.error(ex.getMessage(), ex);
        return ResponseEntity.internalServerError().body(ErrorResponse.from(ErrorCode.INTERNAL_SERVER_ERROR));
    }

}
