package com.rixrod.oboshiefashion.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rixrod.oboshiefashion.models.AppUser;
import com.rixrod.oboshiefashion.models.AuthenticationRequest;
import com.rixrod.oboshiefashion.models.ConfirmationToken;
import com.rixrod.oboshiefashion.models.interfaces.EmailSender;
import com.rixrod.oboshiefashion.repositories.AppUserRepository;
import com.rixrod.oboshiefashion.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@Service
@RequiredArgsConstructor
public class AppUserService implements UserDetailsService {
    private final String USER_NOT_FOUND_MESSAGE = "User with email %s not found";
    @Value("${app.mail.unlock.subject}")
    private String UNLOCK_EMAIL_SUBJECT;
    @Value("${app.mail.unlock.message}")
    private String UNLOCK_EMAIL_MESSAGE;
    @Value("${app.url.unlock}")
    private String ACCOUNT_UNLOCK_LINK;

    private final Logger LOGGER = LoggerFactory.getLogger(AppUserService.class);
    private final String LOGGER_TOPIC = "AppUserService";
    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;
    private final EmailSender emailSender;
    private final EmailService emailService;
    private final PasswordValidatorService passwordValidatorService;
    private final JwtUtil jwtUtil;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        LOGGER.info("{}: LoadUserByUsername running...", LOGGER_TOPIC);
        return appUserRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MESSAGE, email)));
    }

    @Transactional
    public String signUpUser(AppUser appUser){
        LOGGER.info("{}: signUpUser running...", LOGGER_TOPIC);
        boolean userExists = appUserRepository.findByEmail(appUser.getEmail()).isPresent();
        if(userExists){
            //TODo: check if attributes are the same
            //ToDo: Resend mail if user has not been confirmed

            LOGGER.error("{}: Email {} already taken.", LOGGER_TOPIC, appUser.getEmail());
            throw new IllegalStateException(String.format("Email '%s' already taken", appUser.getEmail()));
        }
        String encodedPassword = bCryptPasswordEncoder.encode(appUser.getPassword());
        appUser.setPassword(encodedPassword);
        appUserRepository.save(appUser);
        LOGGER.info("{}: User {} saved.", LOGGER_TOPIC, appUser);

        LOGGER.info("{}: Processing confirmationToken...", LOGGER_TOPIC);
        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(token, LocalDateTime.now(), LocalDateTime.now().plusMinutes(15), appUser);
        confirmationTokenService.saveConfirmationToken(confirmationToken);
        LOGGER.info("{}: ConfirmationToken created", LOGGER_TOPIC);
        return token;
    }

    public String enableAppUser(String email){
        LOGGER.info("{}: enableAppUser running...", LOGGER_TOPIC);
        appUserRepository.enableAppUser(email);
        LOGGER.info("{}: Account enabled for user with email={}", LOGGER_TOPIC, email);
        return "Account enabled";
    }

    public String disableAppUser(String email){
        LOGGER.info("{}: disableAppUser running...", LOGGER_TOPIC);
        appUserRepository.disableAppUser(email);
        LOGGER.info("{}: Account disabled for user with email={}", LOGGER_TOPIC, email);
        return "Account disabled";
    }

    public List<AppUser> getUsers(){
        LOGGER.info("{}: getUsers running...", LOGGER_TOPIC);
        List<AppUser> users = appUserRepository.findAll();
        LOGGER.info("{}: Users found: {}", LOGGER_TOPIC, users);
        return users;
    }

    @Transactional
    public String lockAppUser(String email){
        LOGGER.info("{}: lockAppUser running for user with email={}...", LOGGER_TOPIC, email);
        appUserRepository.lockAppUser(email);
        LOGGER.info("{}: Account locked for user with email={}", LOGGER_TOPIC, email);
        return "Account locked";
    }

    @Transactional
    public String unlockAppUserByToken(String token){
        LOGGER.info("{}: unlockAppUserByToken running...", LOGGER_TOPIC);
        ConfirmationToken confirmationToken = confirmationTokenService
                .getToken(token)
                .orElseThrow(() ->
                        new IllegalStateException("token not found"));

        if (confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("Account already unlocked");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("token expired");
        }

        appUserRepository.unlockAppUser(confirmationToken.getAppUser().getEmail());
        confirmationTokenService.setConfirmedAt(token);
        LOGGER.info("{}: Account unlocked for {}", LOGGER_TOPIC, confirmationToken.getAppUser());
        return "Account unlocked";
    }

    @Transactional
    public String unlockAppUserByEmail(String email){
        LOGGER.info("{}: unlockAppUserByEmail running...", LOGGER_TOPIC);

        appUserRepository.unlockAppUser(email);
        LOGGER.info("{}: Account unlocked for user with email={}", LOGGER_TOPIC, email);
        return "Account unlocked";
    }

    @Transactional
    public String resetPassword(AuthenticationRequest authenticationRequest){
        LOGGER.info("{}: Password reset initiated for ${}", LOGGER_TOPIC, authenticationRequest);
        AppUser user = appUserRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow(() ->
                new UsernameNotFoundException(String.format(this.USER_NOT_FOUND_MESSAGE, authenticationRequest.getEmail())));

        boolean isValidPassword = passwordValidatorService.isPasswordSecured(authenticationRequest.getPassword());
        if (!isValidPassword){
            LOGGER.error("Invalid Password: Password must be at least 8 characters long");
            throw new IllegalStateException("Password must be at least 8 characters long");
        }

        String encodedPassword = bCryptPasswordEncoder.encode(authenticationRequest.getPassword());
        user.setPassword(encodedPassword);
        user.setLocked(true);
        appUserRepository.save(user);
        LOGGER.info("Password has been reset and user account locked... Generating confirmation email now...");

        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(token, LocalDateTime.now(), LocalDateTime.now().plusMinutes(15), user);
        confirmationTokenService.saveConfirmationToken(confirmationToken);

        String link = String.format("%s%s", this.ACCOUNT_UNLOCK_LINK, token);
        emailSender.send(
                user.getEmail(),
                emailService.buildEmail(user.getFirstName(), link, this.UNLOCK_EMAIL_SUBJECT, this.UNLOCK_EMAIL_MESSAGE),
                this.UNLOCK_EMAIL_SUBJECT);
        LOGGER.info("Password reset confirmation email has been sent to ${}", user.getEmail());

        return link;
    }

    public String changePassword(AuthenticationRequest authenticationRequest) {
        LOGGER.info("{}: changePassword initiated for {}", LOGGER_TOPIC, authenticationRequest);
        AppUser user = appUserRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow(() ->
                new UsernameNotFoundException(String.format(this.USER_NOT_FOUND_MESSAGE, authenticationRequest.getEmail())));

        boolean isValidPassword = passwordValidatorService.isPasswordSecured(authenticationRequest.getPassword());
        if (!isValidPassword){
            LOGGER.error("Invalid Password: Password must be at least 8 characters long");
            throw new IllegalStateException("Password must be at least 8 characters long");
        }

        String encodedPassword = bCryptPasswordEncoder.encode(authenticationRequest.getPassword());
        user.setPassword(encodedPassword);
        appUserRepository.save(user);
        LOGGER.info("Password has been changed");

        return "Password changed successfully";
    }

    @Transactional
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOGGER.info("{}: refreshToken running...", LOGGER_TOPIC);
        final String authorizationHeader = request.getHeader(AUTHORIZATION);
        String AUTHORIZATION_HEADER_STARTER = "Oboshie ";
        if (authorizationHeader != null && authorizationHeader.startsWith(AUTHORIZATION_HEADER_STARTER)){
            try {
                String refreshToken = authorizationHeader.substring(AUTHORIZATION_HEADER_STARTER.length());
                String email = jwtUtil.extractEmail(refreshToken);
                AppUser user = (AppUser) this.loadUserByUsername(email);
                if (jwtUtil.validateToken(refreshToken, user)){
                    String accessToken = jwtUtil.createAccessToken(user, request);
                    Map<String, String> tokens = Map.of("access_token", accessToken, "refresh_token", refreshToken);
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), tokens);
                }else{
                    LOGGER.error("{}: Invalid refresh token {}", LOGGER_TOPIC, refreshToken);
                    throw new RuntimeException("Invalid refresh token " + refreshToken);
                }
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
            throw new RuntimeException("Refresh token is missing");
        }
    }
}