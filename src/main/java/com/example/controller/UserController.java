package com.example.controller;

import com.example.main.LoginRequest;
import com.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok().body(userService.login(loginRequest.getMemberId(), ""));
    }

    @PostMapping("/boardWrite")
    public ResponseEntity<String> boardWrite(Authentication authentication) {
        return ResponseEntity.ok().body(authentication.getName() + "님의 리뷰 등록 완료");
    }

    @GetMapping("/test1")
    public String test1() {
        return "test 확인";
    }

    @GetMapping("/test2")
    public @ResponseBody String test2() {
        return "test2 확인";
    }
}