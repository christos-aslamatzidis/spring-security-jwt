package com.example.jwt.model.token;

import com.example.jwt.enums.TokenType;
import com.example.jwt.model.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="token")
public class Token {

    @Id
    @GeneratedValue
    private Long id;

    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    private boolean expired;

    private  boolean revoked;

    private Date expirationDate;

    @ManyToOne
    @JoinColumn(name ="User_id")
    private User user;

}
