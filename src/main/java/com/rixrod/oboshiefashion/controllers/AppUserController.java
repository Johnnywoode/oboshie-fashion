package com.rixrod.oboshiefashion.controllers;

import com.rixrod.oboshiefashion.models.AuthenticationRequest;
import com.rixrod.oboshiefashion.models.RegistrationRequest;
import com.rixrod.oboshiefashion.services.AppUserService;
import com.rixrod.oboshiefashion.services.RegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

@RestController
@RequestMapping(path = "/api/user")
@RequiredArgsConstructor
public class AppUserController {

    private final AppUserService appUserService;
    private final RegistrationService registrationService;

    @PostMapping(path = "/save")
    public ResponseEntity<String>saveUser(@RequestBody RegistrationRequest request){
        String link = this.registrationService.register(request);
        return ResponseEntity.created(URI.create(link)).body("Registration successful");
    }

    @GetMapping(path = "/confirm")
    public ResponseEntity<String> confirmUser(@RequestParam String token){
        return ResponseEntity.ok().body(registrationService.confirmToken(token));
    }

    @GetMapping(path = "/unlock")
    public ResponseEntity<String> unlockUser(@RequestParam String token){
        return ResponseEntity.ok().body(appUserService.unlockAppUserByToken(token));
    }

    @PutMapping(path = "/password/reset")
    public ResponseEntity<String> passwordReset(@RequestBody AuthenticationRequest request){
        String link = this.appUserService.resetPassword(request);
        return ResponseEntity.created(URI.create(link)).body("Password reset successful");
    }

    @GetMapping(path = "/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        appUserService.refreshToken(request, response);
    }

}
