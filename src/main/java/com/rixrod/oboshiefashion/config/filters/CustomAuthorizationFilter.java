package com.rixrod.oboshiefashion.config.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rixrod.oboshiefashion.models.AppUser;
import com.rixrod.oboshiefashion.services.AppUserService;
import com.rixrod.oboshiefashion.utils.JwtUtil;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;

import java.io.IOException;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Component
@AllArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private  final JwtUtil jwtUtil;
    private final AppUserService appUserService;
    private static final Logger LOGGER = LoggerFactory.getLogger(CustomAuthorizationFilter.class);
    private final String LOGGER_TOPIC = "CustomAuthorizationFilter";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/api/user/login") || request.getServletPath().equals("/api/user/token/refresh")){
            filterChain.doFilter(request, response);
        }else{
            final String authorizationHeader = request.getHeader(AUTHORIZATION);

            String AUTHORIZATION_HEADER_STARTER = "Oboshie ";
            if (authorizationHeader != null && authorizationHeader.startsWith(AUTHORIZATION_HEADER_STARTER)){
                try {
                    String jwtToken = authorizationHeader.substring(AUTHORIZATION_HEADER_STARTER.length());
                    String email = jwtUtil.extractEmail(jwtToken);

                    if (email != null && SecurityContextHolder.getContext().getAuthentication() == null){
                        AppUser user = (AppUser) this.appUserService.loadUserByUsername(email);
                        if (jwtUtil.validateToken(jwtToken, user)){
                            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(email, null, user.getAuthorities());
                            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                        }
                    }
                    filterChain.doFilter(request, response);
                }catch (Exception e){
                    LOGGER.error("{}: Error logging in: {}", LOGGER_TOPIC, e.getMessage());
                    response.setHeader("error", e.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    Map<String, String> error = Map.of("error_message", e.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            }else{
                LOGGER.error("{}: AuthorizationHeader={} is either null or AuthorizationHeader must start with \"{}\"", LOGGER_TOPIC, authorizationHeader, AUTHORIZATION_HEADER_STARTER);
                filterChain.doFilter(request, response);
            }

        }
    }
}
