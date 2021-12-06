package me.hellonayeon.jwtauthentication.controller;

import lombok.RequiredArgsConstructor;
import me.hellonayeon.jwtauthentication.dto.JwtResponseDto;
import me.hellonayeon.jwtauthentication.dto.UserRequestDto;
import me.hellonayeon.jwtauthentication.dto.UserTokenRequestDto;
import me.hellonayeon.jwtauthentication.service.UserDetailsImpl;
import me.hellonayeon.jwtauthentication.service.UserService;
import me.hellonayeon.jwtauthentication.util.JwtTokenUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final UserService userService;

    @PostMapping(value = "/user/signup")
    public ResponseEntity<?> createUser(@RequestBody UserRequestDto userRequestDto) {
        return userService.createUser(userRequestDto);
    }

    // FIXME: @AuthenticationPrincipal  or  loadUserByUsername()
    @PostMapping(value = "/user/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody UserRequestDto userRequestDto) {
        return userService.createAuthenticationToken(userRequestDto);
    }

    @PostMapping(value = "/user/token")
    public ResponseEntity<?> reissueAuthenticationToken(@AuthenticationPrincipal UserDetailsImpl userDetails,
                                                        @RequestBody UserTokenRequestDto userTokenRequestDto) {
        return userService.reissueAuthenticationToken(userDetails, userTokenRequestDto);
    }
}
