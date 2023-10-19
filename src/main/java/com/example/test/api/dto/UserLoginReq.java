package com.example.test.api.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class UserLoginReq {
    private String id;
    private String password;
}
