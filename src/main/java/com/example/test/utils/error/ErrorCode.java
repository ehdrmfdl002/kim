package com.example.test.utils.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    BAD_REQUEST(HttpStatus.BAD_REQUEST, -1,"잘못된 요청입니다."),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, -2,"허용되지 않은 메서드입니다."),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, -3,"내부 서버 오류입니다."),
    FORBIDDEN(HttpStatus.FORBIDDEN, -4, "권한이 없는 사용자입니다."),
    MEMBER_NOT_FOUND(HttpStatus.BAD_REQUEST, -7,"사용자를 찾을 수 없습니다."),
    TOKEN_NOT_VALID(HttpStatus.UNAUTHORIZED, -9,"토큰이 유효하지 않습니다."),
    CONFLICT(HttpStatus.CONFLICT, -409, "이미 가입된 회원입니다.");

    private final HttpStatus status;
    private final int code;
    private final String message;
}
