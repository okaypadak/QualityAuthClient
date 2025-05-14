package dev.padak.backend.test;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
public class ProductService {

    List<productDTO> productList = null;

    @PostConstruct
    public void loadProductsFromDB() {
        productList = IntStream.rangeClosed(1, 100).mapToObj(i -> productDTO.builder().id(i)
                        .aciklama("Product " + i)
                        .adet(new Random().nextInt(10))
                        .fiyat(new Random().nextInt(5000)).build()
                ).collect(Collectors.toList());
    }


    public List<productDTO> getProducts() {
        return productList;
    }

    public productDTO getProduct(int id) {
        return productList.stream()
                .filter(tek -> tek.getId() == id)
                .findAny()
                .orElseThrow(() -> new RuntimeException("product " + id + " not found"));
    }


}
