package org.example.service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenProvider {

    private static final int HS256_MIN_BIT_LENGTH = 256;
    private static final String AUTHORITIES_KEY = "authorities";

    @Value("${app.secretKey}")
    private String secretKey;

    @Value("${app.ttl}")
    private long ttl;

    private SecretKey key;

    @PostConstruct
    public void initSecretKey() {
        if (StringUtils.isBlank(secretKey)) {
            throw new IllegalStateException("JWT secret key is not set");
        }
        key = hmacShaKeyFor(secretKey.getBytes());
    }

    /**
     * Generate key from secret using HS256 alg.
     * Due to the WeakKeyException validation introduced in jjwt implementation 0.10.x, we cannot work with legacy token
     * which is created using a weak secret. We now using jjwt 0.9.x to bypass the validation.
     * After https://github.com/jwtk/jjwt/issues/493 is merged, we can upgrade the API version again
     *
     * @param bytes secret
     * @return Secret key
     */
    private static SecretKey hmacShaKeyFor(byte[] bytes) {

        if (bytes == null) {
            throw new IllegalArgumentException("SecretKey byte array cannot be null.");
        }

        int bitLength = bytes.length * 8;

        if (bitLength < HS256_MIN_BIT_LENGTH) {
            log.warn("The specified key byte array is {} bits which is not secure enough for any JWT HMAC-SHA "
                + "algorithm. The JWT JWA Specification (RFC 7518, Section 3.2) "
                + "states that keys used with HMAC-SHA algorithms MUST have a "
                + "size >= 256 bits (the key size must be greater than or equal to the hash "
                + "output size).  See https://tools.ietf.org/html/rfc7518#section-3.2 for more information.",
              bitLength);
        }

        return new SecretKeySpec(bytes, SignatureAlgorithm.HS256.getJcaName());
    }

    /**
     * Generate token
     *
     * @param subjectIdentifier  Identifier of the subject owning the token
     * @param grantedAuthorities Granted authorities
     * @return Long live token
     */
    public String generateToken(String subjectIdentifier, Collection<? extends GrantedAuthority> grantedAuthorities) {
        return Jwts.builder().claim(AUTHORITIES_KEY, grantedAuthorities)
          .subject(subjectIdentifier)
          .issuedAt(new Date())
          .expiration(new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(ttl * 60)))
          .signWith(key)
          .compact();
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().decryptWith(key).build().parseSignedClaims(token).getPayload();
    }

    public UsernamePasswordAuthenticationToken validateToken(String token) {
        if (StringUtils.isBlank(token)) {
            return null;
        }
        try {
            Claims claims = getAllClaimsFromToken(token);
            if (!claims.containsKey(AUTHORITIES_KEY)) {
                return new UsernamePasswordAuthenticationToken(claims.getSubject(), null, AuthorityUtils.NO_AUTHORITIES);
            }

            List<String> authorities = (List<String>)claims.get(AUTHORITIES_KEY);
            return new UsernamePasswordAuthenticationToken(claims.getSubject(), null,
              authorities.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r)).collect(Collectors.toList()));
        } catch (SecurityException | MalformedJwtException e) {
            log.debug("Invalid JWT signature.", e);
        } catch (ExpiredJwtException e) {
            log.debug("Expired JWT token.", e);
        } catch (UnsupportedJwtException e) {
            log.debug("Unsupported JWT token.", e);
        } catch (IllegalArgumentException e) {
            log.debug("JWT token compact of handler are invalid.", e);
        }
        return null;
    }

}
