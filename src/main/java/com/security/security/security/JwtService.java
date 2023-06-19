package com.security.security.security;


import com.security.security.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "CmWtr7yJ8FwPh2jH9stxi4eAIL5WnSyb9aM/c4UszKXK+MdSwGrglXHBmWAL9dPDAVOjR0os9D/CRmQOdadDtWJOr5YM9wW6Jijilj2/IMKgA+b6ub4rR3vI80MF9eKKlIcq4ot347LT+ixABnbm1HwG9vBZzKqNBw7sFrml6Cgw91s3rzBWWQOjvIqPK+cePc0BT38sufTSzMw8kirfLCisIiSetZBchNwGaVCi5g9MUuEpK2RoJkDPydtY6NUzjheZ8zvaBhvx8VdaVuiT60lZav86XlH5coup5tovB8UIsdZqZlsIWUzqLUXs2+socglRkTVsoV4XwFvFF5P0ieJepLnXMrMe207InP8Arl4=\n";
    public String extractUsername(String jwt) {
        return extractClaim(jwt, Claims::getSubject);
    }

    public String generateToken(User userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwt);
        return claimsResolver.apply(claims);
    }

    public String generateToken(Map<String, Object> extractClaims, User userDetails) {
        return Jwts.builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24 * 60))
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String jwt, UserDetails userDetails) {
        final String userEmail = extractUsername(jwt);
        return (userEmail.equals(userDetails.getUsername()) && !isTokenExpired(jwt));
    }

    private boolean isTokenExpired(String jwt) {
        return extractExpiration(jwt).before(new Date());
    }

    private Date extractExpiration(String jwt) {
        return extractClaim(jwt, Claims::getExpiration);
    }


    private Claims extractAllClaims(String jwt) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private Key getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
