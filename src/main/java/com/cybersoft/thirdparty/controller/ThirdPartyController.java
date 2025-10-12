package com.cybersoft.thirdparty.controller;

import com.cybersoft.thirdparty.payload.request.CreateProductRequest;
import com.cybersoft.thirdparty.payload.response.BaseResponse;
import com.cybersoft.thirdparty.utils.SignatureUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/3rd")
public class ThirdPartyController {

    @PostMapping
    public String index(CreateProductRequest productRequest) {
        /**
         * Dùng private key sinh ra được signature
         */
        try{
            PrivateKey privateKey = SignatureUtils.loadPrivateKeyFromResource("private.pem","SHA256withRSA");
            String data = productRequest.getTitle() + "@" + productRequest.getAuthor() + "__" + productRequest.getPrice();
            String signature = SignatureUtils.signWithPrivateKey(privateKey,data.getBytes(StandardCharsets.UTF_8),"SHA256withRSA");

            //call api
            HttpClient client = HttpClient.newHttpClient();
            ObjectMapper objectMapper = new ObjectMapper();
            productRequest.setSignature(signature);
            String requestBody = objectMapper.writeValueAsString(productRequest);

            HttpRequest rqAuthen = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8082/products/api/products"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            HttpResponse<String> respAuthen = client.send(rqAuthen, HttpResponse.BodyHandlers.ofString());
            BaseResponse authenResponse = objectMapper.readValue(respAuthen.body(), BaseResponse.class);
            System.out.println("Kiemtra " + respAuthen.body().toString());
        }catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
        return "success";
    }

}