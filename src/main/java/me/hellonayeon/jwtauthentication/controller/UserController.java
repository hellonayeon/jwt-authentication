package me.hellonayeon.jwtauthentication.controller;

import lombok.RequiredArgsConstructor;
import me.hellonayeon.jwtauthentication.dto.JwtResponseDto;
import me.hellonayeon.jwtauthentication.dto.UserRequestDto;
import me.hellonayeon.jwtauthentication.service.UserDetailsImpl;
import me.hellonayeon.jwtauthentication.service.UserService;
import me.hellonayeon.jwtauthentication.util.JwtTokenUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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

    @PostMapping(value = "/user/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody UserRequestDto userRequestDto) throws Exception {
        authenticate(userRequestDto.getUsername(), userRequestDto.getPassword());
        final UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(userRequestDto.getUsername());
        final String token = jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(new JwtResponseDto(token));
    }

    @PostMapping(value = "/user/signup")
    public ResponseEntity<?> createUser(@RequestBody UserRequestDto userRequestDto) throws Exception {
        userService.registerUser(userRequestDto);
        authenticate(userRequestDto.getUsername(), userRequestDto.getPassword());
        final UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(userRequestDto.getUsername());
        final String token = jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(new JwtResponseDto(token));
    }

    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
