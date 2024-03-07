package com.example.service;

import com.example.util.JwtTokenizer;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


@Service
@NoArgsConstructor(force = true)
public class UserService {

    @Value("${jwt.secretKey}")
    private String secretKey;

    private Long expired = 1000 * 60 * 60L;

    public String login(String memberId, String memberPw) {
        // 인증과정
        return JwtTokenizer.createToken(memberId, secretKey, expired);
    }



}
