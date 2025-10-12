package com.cybersoft.thirdparty.controller;

import com.cybersoft.thirdparty.utils.SignatureUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/3rd")
public class ThirdPartyController {

    
    @PostMapping
    public String index(){
        /*
        * Dùng private key sinh ra đc signature
        * */
        try {
            PrivateKey privatekey = SignatureUtils.loadPrivateKeyFromResource("private.pem","SHA256withRSA");
//            String dataVerify = productRequest.getTitle()+"@"+productRequest.getTitle()+productRequest.getAuthor()+"__"+productRequest.getPrice();

            String data = "a"+"@"+"b"+"__"+40.0;
            String signature = SignatureUtils.signWithPrivateKey(privatekey,data.getBytes(StandardCharsets.UTF_8),"SHA256withRSA");

           return signature;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }
}
