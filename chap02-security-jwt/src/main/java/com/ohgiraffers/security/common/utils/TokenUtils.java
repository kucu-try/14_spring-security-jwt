package com.ohgiraffers.security.common.utils;

import com.ohgiraffers.security.user.entity.User;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.Data;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class TokenUtils {

    private static String jwtSecretKey;
    private static Long tokenValidateTime;

    @Value("${jwt.key}")
    public static void setJwtSecretKey(String jwtSecretKey) {
        TokenUtils.jwtSecretKey = jwtSecretKey;
    }

    @Value("${jwt.time}")
    public static void setTokenValidateTime(Long tokenValidateTime) {
        TokenUtils.tokenValidateTime = tokenValidateTime;
    }

    /**
     * header의 token을 분리하는 메소드
     * @Param header: Authorization의 header값을 가져온다.
     * @return token: Authorization의 token을 반환한다.
    * */
    public static String splitHeader(String header){
        if (!header.equals("")){
            return header.split(" ")[1];
        }else {
            return null;
        }
    }

    /**
     * 유효한 토큰인지 확인하는 메서드
     * @param token : 토큰
     * @return boolean :유효 여부
     * @throws io.jsonwebtoken.ExpiredJwtException, {@link io.jsonwebtoken.JwtException} {@link NullPointerException}
     * */
    public static boolean isValidToken(String token){
       // 이 자체로도 복호화 유효 확인

        try{
            Claims claims = getClaimsFormToken(token);
            return true;
        }catch (ExpiredJwtException e){
            e.printStackTrace();
            return false;
        }catch (JwtException e){
            e.printStackTrace();
            return false;
        }catch (NullPointerException e){
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 토큰을 복호화하는 메서드
     * @param token
     * @return Claims
    * */
    public static Claims getClaimsFormToken(String token){
        return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecretKey))
                .parseClaimsJws(token).getBody();
    }

    /**
     * token을 생성하는 메서드
     * @param user = userEntity
     * @return String token
     * */
    public static String generateJwtToken(User user){
        Date expireTime = new Date(System.currentTimeMillis()+tokenValidateTime);


        JwtBuilder builder = Jwts.builder()
                .setHeader(createHeader())
                .setClaims(createClaims(user))
                .setSubject("ohgiraffers token : " + user.getUserNo())
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(expireTime);

        return builder.compact();

    }

    /**
     * token의 header를 설정하는 부분이다.
     * @return Map<String, Object> header의 설정 정보
     * */
    private static Map<String,Object> createHeader(){
        Map<String, Object> header = new HashMap<>();

        header.put("type", "jwt");
        header.put("alg","HS256");
        header.put("date",System.currentTimeMillis());

        return header;
    }

    /**
     * 사용자 정보를 기반으로 클레임을 생성해주는 메서드
     * @Param user 사용자 정보
     * @return Map<String, Object> claims 정보
     * */
    private static Map<String,Object> createClaims(User user){
        Map<String, Object> claims = new HashMap<>();
        claims.put("userName",user.getUserName());
        claims.put("role",user.getRole());
        claims.put("userEmail",user.getUserEmail());
        return claims;
    }

    /**
     * jwt 서명을 발급해주는 메서드이다.
     * @return key
     * */
    private static Key createSignature(){
        byte[] secretBytes = DatatypeConverter.parseBase64Binary(jwtSecretKey);
        return new SecretKeySpec(secretBytes, SignatureAlgorithm.HS256.getJcaName());
    }



}









