package com.example.test.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Getter
@Slf4j
public class JwtService {

    // TODO: SecretKey 코드에 직접 노출됨 환경변수로 숨길 필요 있음.
    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    @Value("${cookie.access.expiration}")
    private int accessTokenCookieExpirationPeriod;

    @Value("${cookie.refresh.expiration}")
    private int refreshTokenCookieExpirationPeriod;

    @Value("${jwt.access.header}")
    private String accessHeader;

    /**
     * JWT의 Subject와 Claim으로 email 사용 -> 클레임의 name을 "id"으로 설정
     * JWT의 헤더에 들어오는 값 : 'Authorization(Key) = Bearer {토큰} (Value)' 형식
     */
    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String ID_CLAIM = "id";
    private static final String BEARER = "Bearer ";

    /**
     * AccessToken 생성
     */
    public String createAccessToken(String userId) {
        Date now = new Date();
        log.info("지금시간 {}", now);
        return JWT.create() // JWT 토큰을 생성하는 빌더 반환
                .withSubject(ACCESS_TOKEN_SUBJECT) // JWT의 Subject 지정 -> AccessToken이므로 AccessToken
                .withExpiresAt(new Date(now.getTime() + accessTokenExpirationPeriod)) // 토큰 만료 시간 설정
                .withClaim(ID_CLAIM, userId)
                .sign(Algorithm.HMAC512(secretKey)); // HMAC512 알고리즘 사용, application-jwt.yml에서 지정한 secret 키로 암호화
    }

    /**
     * RefreshToken 생성
     * RefreshToken은 Claim에 id도 넣지 않으므로 withClaim() X
     * 그 이유에 RefreshToken은 DB에 저장되기 때문에, id를 토큰안에 넣을 필요가 없음.
     */

    public String createRefreshToken() {
        Date now = new Date();
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime() + refreshTokenExpirationPeriod))
                .sign(Algorithm.HMAC512(secretKey));
    }


    /**
     * REST API에서 사용
     * AccessToken 에서 id 추출
     */
    public String getUserIdFromToken(String token) {
        Optional<String> newToken = Optional.ofNullable(token)
                .map(accessToken -> {
                    try {
                        return URLDecoder.decode(accessToken, "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException(e);
                    }
                });

        if (newToken.isPresent()) {
            DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(secretKey))
                    .build()
                    .verify(newToken.get());

            String userId = decodedJWT.getClaim(ID_CLAIM).asString();  // ID_CLAIM 이름의 클레임에서 문자열 값을 추출하여 변수에 저장

            return userId;
        } else {
            throw new IllegalArgumentException("검증되지 않는 토큰");
        }
    }

    /**
     * Filter에서 사용
     * AccessToken에서 id 추출
     * 추출 전에 JWT.require()로 검증기 생성
     * verify로 AceessToken 검증 후
     * 유효하다면 getClaim()으로 id 추출
     * 유효하지 않다면 빈 Optional 객체 반환
     */
    public Optional<String> extractId(String accessToken) {
        try {
            // 토큰 유효성 검사하는 데에 사용할 알고리즘이 있는 JWT verifier builder 반환
            return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secretKey))
                    .build() // 반환된 빌더로 JWT verifier 생성
                    .verify(accessToken) // accessToken을 검증하고 유효하지 않다면 예외 발생
                    .getClaim(ID_CLAIM) // claim(id) 가져오기
                    .asString());
        } catch (Exception e) {
            log.error("액세스 토큰이 유효하지 않습니다.");
            return Optional.empty();
        }
    }

    public String getUserId(String token) {
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(secretKey))
                .build()
                .verify(token);

        String userId = decodedJWT.getClaim(ID_CLAIM).asString();  // ID_CLAIM 이름의 클레임에서 문자열 값을 추출하여 변수에 저장

        return userId;
    }

    /**
     * AccessToken 헤더 설정
     */
    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        response.setStatus(HttpServletResponse.SC_OK);

        response.setHeader(accessHeader, accessToken);
//        log.info("response : {}", response.getHeader(accessHeader));
        log.info("Access Token 헤더 설정 완료");
        log.info("발급된 Access Token : {}", accessToken);
    }

    /**
     * 헤더에서 AccessToken 추출
     * 토큰 형식 : Bearer XXX에서 Bearer를 제외하고 순수 토큰만 가져오기 위해서
     * 헤더를 가져온 후 "Bearer"를 삭제(""로 replace)
     */
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(accessToken -> accessToken.startsWith(BEARER))
                .map(accessToken -> accessToken.replace(BEARER, ""));
    }


    /**
     * RefreshToken DB 저장(업데이트)
     */
//    @Transactional
//    public void updateRefreshToken(String userId, String refreshToken) {
//        refreshTokenRepository.findByUserId(userId)
//                .ifPresentOrElse(
//                        token -> token.setRefreshToken(refreshToken),
//                        () -> new Exception("일치하는 회원이 없습니다.")
//                );
//    }

    /**
     * 토큰 유효성 검증
     */

    // TODO: UserController에 있는 validate에 있는 로직이랑 대비시켜서 합칠 필요가 있다고 생각됨.
    public boolean isTokenValid(String token) {
        try {
            JWT.require(Algorithm.HMAC512(secretKey)).build().verify(token);
            return true;
        } catch (Exception e) {
            log.error("유효하지 않은 토큰입니다. {}", e.getMessage());
            return false;
        }
    }
}
