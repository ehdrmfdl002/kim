package com.example.test.api.service;

import com.example.test.api.dto.UserLoginReq;
import com.example.test.api.entity.RefreshToken;
import com.example.test.api.entity.User;
import com.example.test.api.repository.RefreshTokenMapper;
import com.example.test.api.repository.UserMapper;
import com.example.test.auth.utils.SecurityUtil;
import com.example.test.jwt.service.JwtService;
import com.example.test.utils.error.CustomException;
import com.example.test.utils.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserMapper userMapper;
    private final RefreshTokenMapper refreshTokenMapper;

    public ResponseEntity normalLogin(HttpServletResponse response, UserLoginReq userLoginReq) {
        String id = userLoginReq.getId();
        String givenPassword = userLoginReq.getPassword();
        System.out.println("id : " + id + " pw : " + givenPassword);
        Optional<User> user = userMapper.selectUserById(id);
        System.out.println(user.get());

        if (user.isPresent() && passwordEncoder.matches(user.get().getPassword(), givenPassword)) {
            User userData = user.get();
            String accessToken = jwtService.createAccessToken(id);
            String refreshToken = jwtService.createRefreshToken();
            Optional<RefreshToken> currentRefreshToken = refreshTokenMapper.selectRefreshTokenById(userData.getId());
            if (currentRefreshToken.isPresent()) {
                RefreshToken newRefreshToken = currentRefreshToken.get();
                newRefreshToken.setRefreshToken(refreshToken);
                refreshTokenMapper.save(id, newRefreshToken.getRefreshToken());
            } else {
                refreshTokenMapper.save(id, refreshToken);
            }
            jwtService.sendAccessToken(response, accessToken);
            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body("ok");
        }
        throw new CustomException(ErrorCode.INTERNAL_SERVER_ERROR);
    }

    public ResponseEntity test() {
        String id = SecurityUtil.extractUsername();
        Optional<RefreshToken> currentRefreshToken = refreshTokenMapper.selectRefreshTokenById(id);
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(currentRefreshToken.get());
    }

    public ResponseEntity sign(UserLoginReq userLoginReq) {
        String role = "USER";
        String id = userLoginReq.getId();
        String password = passwordEncoder.encode(userLoginReq.getPassword());
        userMapper.save(id, password, role);
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(role);
    }

}
