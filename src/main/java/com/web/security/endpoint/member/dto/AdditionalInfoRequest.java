package com.web.security.endpoint.member.dto;

import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdditionalInfoRequest {

	private String password;

	public void encryptPassword(PasswordEncoder passwordEncoder) {
		this.password = passwordEncoder.encode(password);
	}

}
