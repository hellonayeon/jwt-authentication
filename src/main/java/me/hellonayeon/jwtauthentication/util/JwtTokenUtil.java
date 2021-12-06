package me.hellonayeon.jwtauthentication.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import me.hellonayeon.jwtauthentication.dto.JwtResponseDto;
import me.hellonayeon.jwtauthentication.service.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil  implements Serializable {

    private static final Long serialVersionUID = -2550185165626007488L;

    public static final Long ACCESS_TOKEN_EXP_TIME = 30 * 60 * 1000L;

    public static final Long REFRESH_TOKEN_EXP_TIME = 7 * 24  * 60 * 60 * 1000L;

    @Value("${jwt.secret}")
    private String secret;

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }
    //for retrieveing any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    //generate token for user
    public JwtResponseDto generateToken(UserDetailsImpl userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private JwtResponseDto doGenerateToken(Map<String, Object> claims, String subject) {
        JwtBuilder jwtBuilder = Jwts.builder().setClaims(claims)
                                    .setIssuedAt(new Date(System.currentTimeMillis()));

        String accessToken = jwtBuilder.setSubject(subject).signWith(SignatureAlgorithm.HS512, secret).setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXP_TIME)).compact();
        String refreshToken = jwtBuilder.signWith(SignatureAlgorithm.HS512, secret).setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXP_TIME)).compact();

        return new JwtResponseDto(accessToken, refreshToken, REFRESH_TOKEN_EXP_TIME);
    }

    //validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


}