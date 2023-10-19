package com.example.test.utils;

import java.security.SecureRandom;

/**
 * SpringSecurity에서 유저 인증할 때, 비밀번호가 필요함.
 * 소셜로그인의 경우 비밀번호가 필요가 없기 때문에, 임의의 난수를 생성하여 UserDetails에 들어갈 Password에 넣어준다.
 * 즉, 소셜로그인을 통해 로그인할 때마다 해당 유저는 새로운 비밀번호를 UserDetails에 저장하게되는 형식
 * 실질적으로 소셜로그인 유저의 Password는 사용할 일이 없기 때문에, 형식적인 Password임.
 */
public class PasswordUtil {
    private static SecureRandom random = new SecureRandom();
    public static String generateRandomPassword() {
        int index = 0;
        char[] charSet = new char[] {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
        };	//배열안의 문자 숫자는 원하는대로

        StringBuffer password = new StringBuffer();

        for (int i = 0; i < 8 ; i++) {
            double rd = random.nextDouble();
            index = (int) (charSet.length * rd);

            password.append(charSet[index]);
        }
        return password.toString();
    }
}
