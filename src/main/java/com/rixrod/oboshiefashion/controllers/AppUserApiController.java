package com.rixrod.oboshiefashion.controllers;

import com.rixrod.oboshiefashion.models.AppUser;
import com.rixrod.oboshiefashion.models.AuthenticationRequest;
import com.rixrod.oboshiefashion.services.AppUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/api/v1/user")
public class AppUserApiController {

    private final AppUserService appUserService;

    @GetMapping(path = "/all")
    public ResponseEntity<List<AppUser>> getUsers(){ return ResponseEntity.ok().body(appUserService.getUsers()); }

    @PutMapping(path = "/lock")
    public ResponseEntity<String> lockUser(@RequestBody String email){
        return ResponseEntity.ok().body(appUserService.lockAppUser(email));
    }

    @PutMapping(path = "/unlock")
    public ResponseEntity<String> unlockUser(@RequestBody String email){
        return ResponseEntity.ok().body(appUserService.unlockAppUserByEmail(email));
    }

    @PutMapping(path = "/enable")
    public ResponseEntity<String> enableUser(@RequestBody String email){
        return ResponseEntity.ok().body(appUserService.enableAppUser(email));
    }

    @PutMapping(path = "/disable")
    public ResponseEntity<String> disableUser(@RequestBody String email){
        return ResponseEntity.ok().body(appUserService.disableAppUser(email));
    }

    @PutMapping(path = "/password/change")
    public ResponseEntity<String> passwordChange(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok().body(appUserService.changePassword(request));
    }
}
