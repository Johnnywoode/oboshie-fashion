package com.rixrod.oboshiefashion.services;

import com.rixrod.oboshiefashion.models.AppUser;
import com.rixrod.oboshiefashion.models.ConfirmationToken;
import com.rixrod.oboshiefashion.models.RegistrationRequest;
import com.rixrod.oboshiefashion.models.enums.UserRole;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
//@AllArgsConstructor
//@NoArgsConstructor
public class RegistrationService {

    @Value("${app.mail.confirm.subject}")
    private String CONFIRM_EMAIL_SUBJECT;
    @Value("${app.mail.confirm.message}")
    private String CONFIRM_EMAIL_MESSAGE;
    @Value("${app.url.confirm}")
    private String ACCOUNT_CONFIRM_LINK;

    private static final Logger LOGGER = LoggerFactory.getLogger(RegistrationService.class);
    private final String LOGGER_TOPIC = "RegistrationService";
    private final AppUserService appUserService;
    private final EmailValidator emailValidator;
    private final ConfirmationTokenService confirmationTokenService;
//    private final EmailSender emailSender;
    private final PasswordValidatorService passwordValidatorService;
    private final EmailService emailService;

    @Transactional
    public String register( RegistrationRequest request) {
        LOGGER.info("{}: register running...", LOGGER_TOPIC);
        boolean isValidEmail = emailValidator.
                test(request.getEmail());
        if (!isValidEmail) {
            LOGGER.error("{}: Email not valid", LOGGER_TOPIC);
            throw new IllegalStateException("Email not valid");
        }

        boolean isValidPassword = passwordValidatorService.isPasswordSecured(request.getPassword());
        if (!isValidPassword) {
            LOGGER.error("{}: Password must be at least 8 characters long", LOGGER_TOPIC);
            throw new IllegalStateException("Password must be at least 8 characters long");
        }
        String token = appUserService.signUpUser(
                new AppUser(
                        request.getFirstName(),
                        request.getLastName(),
                        request.getEmail(),
                        request.getTel(),
                        request.getPassword(),
                        UserRole.USER
                )
        );
        LOGGER.info("{}: New user saved", LOGGER_TOPIC);
        LOGGER.info("{}: Processing confirmation email", LOGGER_TOPIC);
        String link = String.format("%s%s", ACCOUNT_CONFIRM_LINK, token);
//        URI link = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/v1/authentication/confirm?token=" + token).toUriString());
        emailService.send(
                request.getEmail(),
                emailService.buildEmail(request.getFirstName(), link, CONFIRM_EMAIL_SUBJECT, CONFIRM_EMAIL_MESSAGE),
                CONFIRM_EMAIL_SUBJECT
        );
        LOGGER.info("{}: Confirmation email sent to email {}", LOGGER_TOPIC, request.getEmail());

        return link;
    }

    @Transactional
    public String confirmToken(String token) {
        LOGGER.info("{}: confirmToken running for token={}...", LOGGER_TOPIC, token);
        ConfirmationToken confirmationToken = confirmationTokenService
                .getToken(token)
                .orElseThrow(() ->
                        new IllegalStateException("Token not found"));

        if (confirmationToken.getConfirmedAt() != null) {
            LOGGER.error("{}: Email already confirmed", LOGGER_TOPIC);
            throw new IllegalStateException("Email already confirmed");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            LOGGER.error("{}: Token expired", LOGGER_TOPIC);
            throw new IllegalStateException("Token expired");
        }

        confirmationTokenService.setConfirmedAt(token);
        appUserService.enableAppUser(
                confirmationToken.getAppUser().getEmail());

        LOGGER.info("{}: Token confirmed for user {}", LOGGER_TOPIC, confirmationToken.getAppUser());
        return "Token confirmed";
    }
}
