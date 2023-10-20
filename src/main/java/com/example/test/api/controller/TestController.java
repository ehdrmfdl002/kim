package com.example.test.api.controller;

import com.example.test.api.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin
public class TestController {
    private final UserService userService;

    @GetMapping("/test")
    public ResponseEntity test(@RequestHeader("Authorization") String token) throws Exception {
        return userService.test(token);
    }
}
