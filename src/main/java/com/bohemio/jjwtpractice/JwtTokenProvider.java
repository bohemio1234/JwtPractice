package com.bohemio.jjwtpractice;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final SecretKey secretKey;
    private final long tokenValidityInSeconds;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKeyString, @Value("${jwt.expiration-in-ms") long tokenValidityInSeconds) {
        this.secretKey = Keys.hmacShaKeyFor( secretKeyString.getBytes() ); //string을 바이트로. 키는 보통 바이트배열형태라서.
        this.tokenValidityInSeconds = tokenValidityInSeconds;
        System.out.println( "비밀키 로딩 완료!" );
    }

    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map( GrantedAuthority::getAuthority ) //각 grantedAuthority객체에서 권한 이름만 쏙! ex) [ROLE_USER, ROLE_ADMIN]
                .collect( Collectors.joining( "," ) ); // = "ROLE_USER,ROLE_ADMIN"
        //이걸 왜 이렇게 햐냐면,, claim엔 보통 문자열이 들어가야함..

        Date now = new Date();
        Date validity = new Date( now.getTime() + this.tokenValidityInSeconds );

        Claims claims = Jwts.claims()
                .subject(authentication.getName())
                .add("auth", authorities)
                .issuedAt( now )
                .expiration( validity )
                .build();

        return Jwts.builder()
                .claims(claims)
                .signWith( secretKey )
                .compact();
    } //그니까 이 함수는 로그인할떄 딱 한번 실행됨..

    //밑부턴 위에 만들어진 JWT가 진짜인지, 유효한지 검증하고, 그 안에 숨겨진 정보들을 뽑아내는 메소드


    // 토큰에서 Claims 추출 (내부적으로 서명 검증 포함)
    private Claims getClaimsFromToken(String token) throws JwtException {
        return Jwts.parser() //parser은 토큰 해석 검증 준비
                .verifyWith(secretKey) // setSigningKey 대신 verifyWith(SecretKey) 사용
                .build()
                .parseSignedClaims(token) // parseClaimsJws 대신 parseSignedClaims, 반환 타입 Jws<Claims> -> Claims
                .getPayload();            // getBody() 대신 getPayload()
    }

    public String getUsername(String token) {
        try {
            return getClaimsFromToken(token).getSubject();
        } catch (ExpiredJwtException e) {
            logger.warn("만료된 JWT 토큰입니다: {}", e.getMessage());
            return e.getClaims().getSubject(); // 만료된 토큰이라도 subject는 읽을 수 있게 (선택적)
        } catch (JwtException e) {
            logger.warn("유효하지 않은 JWT 토큰입니다 (getUsername): {}", e.getMessage());
            return null;
        }
    }

    // 🛡️ 토큰에서 인증 정보(Authentication 객체) 조회
    public Authentication getAuthentication(String token) {
        // 2️⃣ 토큰을 다시 한번 파싱해서 내용물(Claims)을 꺼내자!

        Claims claims = getClaimsFromToken(token);
        String username = claims.getSubject();

        // 4️⃣ 우리가 "auth"라는 이름으로 저장했던 권한 정보 문자열을 꺼내서,
        //    실제 GrantedAuthority 객체들의 컬렉션으로 변환! (쉼표로 구분했었죠?)
        //이 긴 문자열을 spring security가 이해할수있는 컬렉션묶음으로 다시 줘야함.
        //split하면 문자열에잇는내용을 ,기준으로 배열로 나눠주는것.
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get( "auth", String.class ).split( "," ) ) // "auth" 클레임을 문자열로 가져와 쉼표로 쪼갬
                        .filter( auth -> !auth.trim().isEmpty() ) // 혹시 모를 빈 문자열 제거
                        .map( SimpleGrantedAuthority::new ) // 각 권한 문자열을 SimpleGrantedAuthority 객체로 변환 (이건 GrantedAuthority구현체)
                        .collect( Collectors.toList() );    // 리스트로 모음

        // 5️⃣ UserDetails 객체를 만들자! (여기서는 간단하게 User 객체 사용)
        //    토큰 기반 인증에서는 비밀번호는 이미 검증되었으므로 보통 빈 문자열("") 처리.
        UserDetails userDetails = new User( username, "", authorities );

        // 6️⃣ 최종적으로 Authentication 객체를 만들어서 반환!
        //    이 객체가 SecurityContextHolder에 저장되어 "현재 사용자는 인증되었다"는 것을 시스템에 알림.
        return new UsernamePasswordAuthenticationToken( userDetails, "", authorities );

    }

    // ✅ 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String token) {
        try {
            // 7️⃣ 토큰을 파싱하고 서명을 검증. 문제가 있으면 여기서 예외가 빵!
            getClaimsFromToken(token);
            return true; // 예외 없이 통과하면? "이 토큰은 유효하다!"
        } catch (JwtException | IllegalArgumentException e) {
            // 8️⃣ 뭔가 문제가 생겼다면 (예: 서명 불일치, 만료된 토큰, 잘못된 형식 등)
            //    어떤 문제인지 로그로 남겨주면 디버깅에 좋겠죠?
            logger.warn("유효하지 않은 JWT 토큰입니다.", e); // logger는 SLF4J 같은 로깅 프레임워크 사용
            // System.err.println("유효하지 않은 JWT 토큰입니다: " + e.getMessage()); // 간단하게는 이렇게!
        }
        return false; // 문제가 있었으니 "이 토큰은 유효하지 않다!"
    }
    //이 함수는 클라이언 모든 http요청에 대해 수행됨.

}
