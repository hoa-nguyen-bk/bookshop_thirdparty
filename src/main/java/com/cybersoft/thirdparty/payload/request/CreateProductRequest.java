package com.cybersoft.thirdparty.payload.request;

import java.util.List;

public class CreateProductRequest {
    private String title;
    private String author;
    private int review;
    private double price;
    private List<FileRequest> files;
    private String signature;

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public int getReview() {
        return review;
    }

    public void setReview(int review) {
        this.review = review;
    }

    public double getPrice() {
        return price;
    }

    public void setPrice(double price) {
        this.price = price;
    }

    public List<FileRequest> getFiles() {
        return files;
    }

    public void setFiles(List<FileRequest> files) {
        this.files = files;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
