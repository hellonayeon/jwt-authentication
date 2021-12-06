package me.hellonayeon.jwtauthentication.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class JwtResponseDto {
    private final String accessToken;
}