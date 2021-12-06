package me.hellonayeon.jwtauthentication.service;

import lombok.RequiredArgsConstructor;
import me.hellonayeon.jwtauthentication.domain.User;
import me.hellonayeon.jwtauthentication.dto.JwtResponseDto;
import me.hellonayeon.jwtauthentication.dto.UserRequestDto;
import me.hellonayeon.jwtauthentication.dto.UserTokenRequestDto;
import me.hellonayeon.jwtauthentication.repository.UserRepository;
import me.hellonayeon.jwtauthentication.util.JwtTokenUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
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
    private final UserDetailsService userDetailsService;
    private final RedisTemplate redisTemplate;

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;


    @Transactional
    public ResponseEntity<?> createUser(UserRequestDto userRequestDto) {
        String username = userRequestDto.getUsername();
        // 사용자이름 중복 확인
        Optional<User> found = userRepository.findByUsername(username);
        if (found.isPresent()) {
            throw new IllegalArgumentException("중복된 사용자 이름이 존재합니다.");
        }

        String password = passwordEncoder.encode(userRequestDto.getPassword());

        User user = new User(username, password);
        userRepository.save(user);

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userRequestDto.getUsername(), userRequestDto.getPassword()));

        final UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(userRequestDto.getUsername());
        final JwtResponseDto jwtTokenInfo = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(jwtTokenInfo);
    }

    public ResponseEntity<?> createAuthenticationToken(UserRequestDto userRequestDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userRequestDto.getUsername(), userRequestDto.getPassword()));

        final UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(userRequestDto.getUsername());
        final JwtResponseDto jwtTokenInfo = jwtTokenUtil.generateToken(userDetails);

        redisTemplate.opsForValue().set("RT:" + authentication.getName(), jwtTokenInfo.getRefreshToken(), jwtTokenInfo.getRefreshTokenExpTime(), TimeUnit.MILLISECONDS);

        return ResponseEntity.ok(jwtTokenInfo);
    }

    public ResponseEntity<?> reissueAuthenticationToken(UserDetailsImpl userDetails, UserTokenRequestDto userTokenRequestDto) {
        // 사용자로부터 받은 Refresh Token 유효성 검사
        if(!jwtTokenUtil.validateToken(userTokenRequestDto.getRefreshToken(), userDetails)) {
            throw new IllegalArgumentException("잘못된 요청입니다. 다시 로그인해주세요.");
        }

        // Redis 에 저장된 Refresh Token 과 비교
        String refreshToken = (String) redisTemplate.opsForValue().get("RT:" + userDetails.getUsername());
        if(ObjectUtils.isEmpty(refreshToken)) {
            throw new IllegalArgumentException("잘못된 요청입니다. 다시 로그인해주세요.");
        }
        if(!refreshToken.equals(userTokenRequestDto.getRefreshToken())) {
            throw new IllegalArgumentException("Refresh Token 정보가 일치하지 않습니다.");
        }

        // 새로운 토큰 발급
        final JwtResponseDto jwtTokenInfo = jwtTokenUtil.generateToken(userDetails);

        // Redis 업데이트
        redisTemplate.opsForValue().set("RT:" + userDetails.getUsername(), jwtTokenInfo.getRefreshToken(), jwtTokenInfo.getRefreshTokenExpTime(), TimeUnit.MILLISECONDS);

        return ResponseEntity.ok(jwtTokenInfo);
    }
}
