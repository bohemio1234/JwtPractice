 import com.bohemio.jjwtpractice.JwtTokenProvider;
 import org.junit.jupiter.api.BeforeEach;
 import org.junit.jupiter.api.Test;
 import org.mockito.Mockito; // Mockito 사용 시
 import org.springframework.security.core.Authentication;
 import static org.junit.jupiter.api.Assertions.*;
 import static org.mockito.Mockito.when;

 public class JwtTokenProviderTest {

     private JwtTokenProvider jwtTokenProvider;
     private String testSecretKey = "testSecretKeyForJwtTokenProviderUnitTests"; // 테스트용 비밀키
     private long testTokenValidityInMs = 3600000; // 1시간

     @BeforeEach
     void setUp() {
         // 테스트용 JwtTokenProvider 직접 생성 (Spring 컨텍스트 없이)
         jwtTokenProvider = new JwtTokenProvider(testSecretKey, testTokenValidityInMs);
     }

     @Test
     void 토큰생성_및_사용자이름추출_정상() {
         // given
         Authentication mockAuthentication = Mockito.mock(Authentication.class);
         when(mockAuthentication.getName()).thenReturn("testUser");
         // 권한 설정 등 추가적인 mock 설정 가능

         // when
         String token = jwtTokenProvider.createToken(mockAuthentication);
         String usernameFromToken = jwtTokenProvider.getUsername(token);

         // then
         assertNotNull(token);
         assertEquals("testUser", usernameFromToken);
         assertTrue(jwtTokenProvider.validateToken(token)); // 방금 만든 토큰은 유효해야 함
     }

     @Test
     void 만료된_토큰_검증_실패() throws InterruptedException {
         // given
         JwtTokenProvider shortLivedTokenProvider = new JwtTokenProvider(testSecretKey, 10); // 10ms 유효 토큰
         Authentication mockAuthentication = Mockito.mock(Authentication.class);
         when(mockAuthentication.getName()).thenReturn("testUser");
         String expiredToken = shortLivedTokenProvider.createToken(mockAuthentication);

         Thread.sleep(20); // 10ms 보다 더 길게 대기해서 토큰을 만료시킴

         // when
         boolean isValid = jwtTokenProvider.validateToken(expiredToken); // 원래 provider로 검증

         // then
         assertFalse(isValid);
     }
 }