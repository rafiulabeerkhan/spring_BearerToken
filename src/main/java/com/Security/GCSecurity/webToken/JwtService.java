package com.Security.GCSecurity.webToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.sql.Date;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
@Service
public class JwtService {
private static final String SECRET = "442216F8C8577FC9BFEAE0A5809D130F5CE73F688A00F826216C2174F7EFB2B228EB64F45558D6B2E55C2A8FDA0E212F7788365B60FED701AF1EAC21DF173FA7";
private static final long VALIDITY = TimeUnit.MINUTES.toMillis(60);

public String generateToken(UserDetails userDetails){
    Map<String, String> claims = new HashMap<>();
    claims.put("iss","https://secure.genuinecoder.com");
  return   Jwts.builder()
            .claims(claims)
            .subject(userDetails.getUsername())
            .issuedAt(Date.from(Instant.now()))
            .expiration(Date.from(Instant.now().plusMillis(VALIDITY)))
            .signWith(generateKey())
            .compact();

}

private SecretKey generateKey(){
    byte[] decodeKey = Base64.getDecoder().decode(SECRET);
    return Keys.hmacShaKeyFor(decodeKey);
}


    public String extractUsername(String jwt) {
        Claims claims = getClaims(jwt);
        return claims.getSubject();
    }

    private Claims getClaims(String jwt) {
     return Jwts.parser()
                .verifyWith(generateKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();

    }

    public boolean isTokenValid(String jwt) {
    Claims claims = getClaims(jwt);
    return claims.getExpiration().after(Date.from(Instant.now()));
    }
}
