package com.web.security.endpoint.login.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {  // POJO (Plain ~ JAVA Object) 아무것도 영향받지 않는 순수한 자바 객체

    private String email;
    private String password;
}
