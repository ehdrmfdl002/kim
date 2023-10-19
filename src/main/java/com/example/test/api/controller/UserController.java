package com.example.test.api.controller;

import com.example.test.api.dto.UserLoginReq;
import com.example.test.api.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin
public class UserController {
    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity normalLogin(HttpServletResponse response, @RequestBody UserLoginReq userLoginReq) throws Exception {
        return userService.normalLogin(response, userLoginReq);
    }

    @GetMapping("/test")
    public ResponseEntity test(@RequestHeader("Authorization") String token) throws Exception {
        return userService.test(token);
    }
}
