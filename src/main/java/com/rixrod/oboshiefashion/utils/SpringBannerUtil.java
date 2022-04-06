package com.rixrod.oboshiefashion.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.Banner;
import org.springframework.core.env.Environment;

import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.PrintStream;


public class SpringBannerUtil implements Banner {
    private int WIDTH = 200;
    private int HEIGHT = 20;

    @Value("${spring.profiles.active:**}")
    private String ENV;

    @Override
    public void printBanner(Environment environment, Class<?> sourceClass, PrintStream out) {
        BufferedImage image = new BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_INT_RGB);
        Graphics g = image.getGraphics();
        g.setFont(new Font("SansSerif", Font.BOLD, 18));

        Graphics2D graphics = (Graphics2D) g;
        graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        graphics.drawString(ENV + " @ Rixrod", 10, 20);

        for (int y = 0; y < HEIGHT; y++) {
            StringBuilder sb = new StringBuilder();
            for (int x = 0; x < WIDTH; x++) {

                sb.append(image.getRGB(x, y) == -16777216 ? " " : "0");

            }

            if (sb.toString().trim().isEmpty()) {
                continue;
            }

            System.out.println(sb);

//            Files.write(Paths.get("D:\\ascii-art"), "png");
        }
    }
}
