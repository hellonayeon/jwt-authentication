package me.hellonayeon.jwtauthentication.service;

import lombok.RequiredArgsConstructor;
import me.hellonayeon.jwtauthentication.domain.User;
import me.hellonayeon.jwtauthentication.dto.UserRequestDto;
import me.hellonayeon.jwtauthentication.repository.UserRepository;
import me.hellonayeon.jwtauthentication.util.JwtTokenUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public void registerUser(UserRequestDto userRequestDto) {
        String username = userRequestDto.getUsername();
        // 사용자이름 중복 확인
        Optional<User> found = userRepository.findByUsername(username);
        if (found.isPresent()) {
            throw new IllegalArgumentException("중복된 사용자 이름이 존재합니다.");
        }

        String password = passwordEncoder.encode(userRequestDto.getPassword());

        User user = new User(username, password);
        userRepository.save(user);
    }
}
