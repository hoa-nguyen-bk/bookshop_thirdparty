package com.cybersoft.thirdparty.controller;

import com.cybersoft.thirdparty.payload.request.BillRequest;
import com.cybersoft.thirdparty.payload.request.CreateProductRequest;
import com.cybersoft.thirdparty.payload.response.BaseResponse;
import com.cybersoft.thirdparty.utils.SignatureUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

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

    @PostMapping("/bill")
    public String bill(@RequestBody BillRequest billRequest) {
        try{
            // call api
            HttpClient client = HttpClient.newHttpClient();
            ObjectMapper objectMapper = new ObjectMapper();

            String requestBody = objectMapper.writeValueAsString(billRequest);

            PublicKey key = SignatureUtils.loadPublicKeyFromResource("public_decscript_enc.pem", "SHA256withRSA");
            byte[] encrypt = SignatureUtils.rsaEncryptOaep(
                    key,
                    requestBody.getBytes(StandardCharsets.UTF_8)
            );

            String base64Encrypt = Base64.getEncoder().encodeToString(encrypt);

            System.out.println("Ma hoa: " + base64Encrypt);

            HttpRequest rqAuthen = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8082/products/api/products"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            HttpResponse<String> respAuthen = client.send(rqAuthen, HttpResponse.BodyHandlers.ofString());
            BaseResponse authenResponse = objectMapper.readValue(respAuthen.body(), BaseResponse.class);
            System.out.println("Kiemtra " + authenResponse.toString());
        }catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
        return "success";
    }
}