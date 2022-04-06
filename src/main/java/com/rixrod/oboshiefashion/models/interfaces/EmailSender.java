package com.rixrod.oboshiefashion.models.interfaces;

public interface EmailSender {
    void send(String to, String email, String subject);
}
