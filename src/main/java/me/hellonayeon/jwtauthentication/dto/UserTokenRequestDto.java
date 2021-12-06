package me.hellonayeon.jwtauthentication.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserTokenRequestDto {
    private String accessToken;
    private String refreshToken;
}
