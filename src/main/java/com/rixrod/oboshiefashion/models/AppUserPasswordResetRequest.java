package com.rixrod.oboshiefashion.models;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class AppUserPasswordResetRequest {
    private String email;
    private String newPassword;
}
