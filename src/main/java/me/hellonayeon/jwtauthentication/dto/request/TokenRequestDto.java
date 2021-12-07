package me.hellonayeon.jwtauthentication.dto.request;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class TokenRequestDto {
//    private String username;
    private String accessToken;
    private String refreshToken;
}
