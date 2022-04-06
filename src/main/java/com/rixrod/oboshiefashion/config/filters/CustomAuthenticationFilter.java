package com.rixrod.oboshiefashion.config.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rixrod.oboshiefashion.models.AppUser;
import com.rixrod.oboshiefashion.utils.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String email = request.getParameter("email");
        String password = request.getParameter("password");
        log.info("Authentication attempt for email: {} and password: {}", email, password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);
        log.info("Authentication token {} generated for {} ", authenticationToken, email);
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        log.info("Authentication done for {} as {} ", email, authentication);
        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        AppUser user = (AppUser) authentication.getPrincipal();
        response.setContentType(APPLICATION_JSON_VALUE);
        JwtUtil jwtUtil = new JwtUtil();
        new ObjectMapper().writeValue(response.getOutputStream(), jwtUtil.generateTokens(user, request));
    }
}
