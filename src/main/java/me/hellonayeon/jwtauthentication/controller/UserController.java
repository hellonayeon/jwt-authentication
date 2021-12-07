package me.hellonayeon.jwtauthentication.controller;

import lombok.RequiredArgsConstructor;
import me.hellonayeon.jwtauthentication.domain.User;
import me.hellonayeon.jwtauthentication.dto.request.UserRequestDto;
import me.hellonayeon.jwtauthentication.dto.request.TokenRequestDto;
import me.hellonayeon.jwtauthentication.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping(value = "/user/signup")
    public User createUser(@RequestBody UserRequestDto userRequestDto) {
        return userService.createUser(userRequestDto);
    }

    @PostMapping(value = "/user/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody UserRequestDto userRequestDto) {
        return userService.createAuthenticationToken(userRequestDto);
    }

    @PostMapping(value = "/user/token")
    public ResponseEntity<?> reissueAuthenticationToken(@RequestBody TokenRequestDto tokenRequestDto) {
        return userService.reissueAuthenticationToken(tokenRequestDto);
    }
}
