package com.rixrod.oboshiefashion.services;

import org.springframework.stereotype.Service;

@Service
public class PasswordValidatorService {
    private final int MIN_PASSWORD_LENGTH = 8;
    public boolean isPasswordSecured(String password){
        return password.length() >= MIN_PASSWORD_LENGTH;
    }
}