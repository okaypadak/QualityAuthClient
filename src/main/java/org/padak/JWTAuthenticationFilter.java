package org.padak;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    private final JwtService jwtService;

    public JWTAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        logger.debug("📥 İstek geldi: {} {}", request.getMethod(), request.getRequestURI());

        if (Objects.isNull(authHeader)) {
            logger.warn("❌ Authorization header hiç yok");
            filterChain.doFilter(request, response);
            return;
        }

        if (!authHeader.startsWith("Bearer ")) {
            logger.warn("❌ Authorization header Bearer ile başlamıyor: {}", authHeader);
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        logger.debug("🔑 Bearer token: {}", jwt);

        try {
            final String username = jwtService.extractUsername(jwt);
            final Claims claims = jwtService.extractAllClaims(jwt);
            logger.debug("👤 Token'dan username: {}", username);
            logger.debug("📄 Token Claims: {}", claims);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                List<String> roles = claims.get("roles", List.class);
                logger.debug("🔐 Token roles: {}", roles);

                List<SimpleGrantedAuthority> authorities = roles != null
                        ? roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
                        : Collections.emptyList();

                logger.debug("✅ Yüklenecek yetkiler: {}", authorities);

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        authorities
                );

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);
                logger.info("✅ Kullanıcı doğrulandı ve security context'e eklendi: {}", username);
            }
        } catch (Exception e) {
            logger.error("💥 Token işlenirken hata oluştu: {}", e.getMessage(), e);
            // Burada response'a manuel 401 yazmak yerine devam ediyoruz ki spring security handle etsin
        }

        filterChain.doFilter(request, response);
    }
}
