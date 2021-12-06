package me.hellonayeon.jwtauthentication.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class JwtResponseDto {
    private final String accessToken;
    private final String refreshToken;
    private final Long refreshTokenExpTime;
}