package com.example.JWTImplemenation.Entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="_watch")
public class Watch {
    @Id
    @GeneratedValue
    private Integer id;
    private String name;
    private String brand;
    private Date createdDate;
    private String description;
    private Integer price;
    private String yearOfProduction;
    private String material;
    private String thickness;
    private String dial;
    private String movement;
    private String crystal;
    private String bracket;
    private String buckle;
    @OneToMany(mappedBy = "watch")
    private List<ImageUrl> images;
}
