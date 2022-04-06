package com.rixrod.oboshiefashion;

import com.rixrod.oboshiefashion.utils.SpringBannerUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@AllArgsConstructor
@Slf4j
public class OboshieFashionApplication {
	private static final SpringBannerUtil springBannerUtil = new SpringBannerUtil();
	@Value("${my.greeting}")
	private static String greeting;

	public static void main(String[] args){
		log.info("********* " +greeting);
		SpringApplication.run(OboshieFashionApplication.class, args);
//		SpringApplication.setBanner(springBannerUtil);
	}
}
