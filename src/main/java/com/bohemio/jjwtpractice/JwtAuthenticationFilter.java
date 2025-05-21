package com.bohemio.jjwtpractice;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,      // 지금 들어온 요청!
                                    HttpServletResponse response,     // 우리가 보낼 응답!
                                    FilterChain filterChain) throws ServletException, IOException { // 다음 필터로 넘겨줄 통로!

        // 5️⃣ 요청 헤더에서 JWT 토큰을 한번 꺼내볼까? (아래 resolveToken 메소드 참고)
        String token = resolveToken( request );

        // 6️⃣ 토큰이 실제로 존재하고, 우리 JwtTokenProvider가 보기에 유효한 토큰이라면?
        if (StringUtils.hasText( token ) && jwtTokenProvider.validateToken( token )) {
            // 7️⃣ 토큰이 유효하네! 그럼 토큰에서 인증 정보(Authentication 객체)를 꺼내자!
            Authentication authentication = jwtTokenProvider.getAuthentication( token );
            // 8️⃣ 꺼내온 인증 정보를 SecurityContextHolder에 쏙! 저장! (이제 이 요청은 인증된 사용자의 요청이다!)
            SecurityContextHolder.getContext().setAuthentication( authentication );
            logger.debug( "Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), request.getRequestURI() );
        } else {
            logger.debug( "유효한 JWT 토큰이 없습니다, uri: {}", request.getRequestURI() );
        }

        // 9️⃣ 자, 우리 필터가 할 일은 끝났으니 다음 필터로 요청과 응답을 넘겨주자! (이거 빼먹으면 큰일나요!)
        filterChain.doFilter( request, response );

    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization"); // "Authorization" 헤더를 꺼내고
        // "Bearer " 로 시작하는 토큰인지, 그리고 실제로 텍스트가 있는지 확인
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // "Bearer " 7글자 뒤부터가 진짜 토큰!
        }
        return null; // 없으면 null 반환
    }


}
