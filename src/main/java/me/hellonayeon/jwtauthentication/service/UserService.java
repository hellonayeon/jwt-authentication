package me.hellonayeon.jwtauthentication.service;

import lombok.RequiredArgsConstructor;
import me.hellonayeon.jwtauthentication.domain.User;
import me.hellonayeon.jwtauthentication.dto.response.JwtTokenResponseDto;
import me.hellonayeon.jwtauthentication.dto.request.UserRequestDto;
import me.hellonayeon.jwtauthentication.dto.request.TokenRequestDto;
import me.hellonayeon.jwtauthentication.repository.UserRepository;
import me.hellonayeon.jwtauthentication.util.JwtTokenUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class UserService {

    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;
    private final RedisTemplate redisTemplate;

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;


    @Transactional
    public User createUser(UserRequestDto userRequestDto) {
        String username = userRequestDto.getUsername();
        // 사용자이름 중복 확인
        Optional<User> found = userRepository.findByUsername(username);
        if (found.isPresent()) {
            throw new IllegalArgumentException("중복된 사용자 이름이 존재합니다.");
        }

        String password = passwordEncoder.encode(userRequestDto.getPassword());

        User user = new User(username, password);
        return userRepository.save(user);
    }

    public ResponseEntity<?> createAuthenticationToken(UserRequestDto userRequestDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userRequestDto.getUsername(), userRequestDto.getPassword()));

        final String accessToken = jwtTokenUtil.generateAccessToken(userRequestDto.getUsername());
        final String refreshToken = jwtTokenUtil.generateRefreshToken();

        // Redis 에 Refresh Token 저장
        redisTemplate.opsForValue().set("RT:" + authentication.getName(), refreshToken, JwtTokenUtil.REFRESH_TOKEN_EXP_TIME, TimeUnit.MILLISECONDS);

        return ResponseEntity.ok(new JwtTokenResponseDto(accessToken, refreshToken));
    }

    public ResponseEntity<?> reissueAuthenticationToken(TokenRequestDto tokenRequestDto) {
        // 사용자로부터 받은 Refresh Token 유효성 검사
        // Refresh Token 마저 만료되면 다시 로그인
        if(jwtTokenUtil.isTokenExpired(tokenRequestDto.getRefreshToken()) || !jwtTokenUtil.validateToken(tokenRequestDto.getRefreshToken())) {
            throw new IllegalArgumentException("잘못된 요청입니다. 다시 로그인해주세요.");
        }

        // Access Token 에 기술된 사용자 이름 가져오기
        String username = jwtTokenUtil.getUsernameFromToken(tokenRequestDto.getAccessToken());

        // Redis 에 저장된 Refresh Token 과 비교
        String refreshToken = (String) redisTemplate.opsForValue().get("RT:" + username);
        if(ObjectUtils.isEmpty(refreshToken)) {
            throw new IllegalArgumentException("잘못된 요청입니다. 다시 로그인해주세요.");
        }
        if(!refreshToken.equals(tokenRequestDto.getRefreshToken())) {
            throw new IllegalArgumentException("Refresh Token 정보가 일치하지 않습니다.");
        }

        // 새로운 Access Token 발급
        final String accessToken = jwtTokenUtil.generateAccessToken(username);

        return ResponseEntity.ok(new JwtTokenResponseDto(accessToken));
    }
}
