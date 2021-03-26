package com.upgrad.FoodOrderingApp.service.entity;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;

@Entity
@Table(name = "CUSTOMER")
@NamedQueries(
        {
                @NamedQuery(name = "findByContactNumber", query = "SELECT c from CustomerEntity c where c.contact_number = :contactNumber"),
                @NamedQuery(name = "findByUuid", query = "SELECT c from CustomerEntity c where c.uuid = :uuid")
        }
)
public class CustomerEntity implements Serializable {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;

    @Column(name = "uuid")
    @NotNull
    @Size(max = 200)
    private String uuid;

    @Column(name = "firstname")
    @NotNull
    @Size(max = 30)
    private String firstname;

    @Column(name = "lastname")
    @Size(max = 30)
    private String lastname;

    @Column(name = "email")
    @Size(max = 30)
    private String email;

    @Column(name = "contact_number")
    @Size(max = 30)
    @NotNull
    private String contact_number;

    @Column(name = "password")
    @Size(max = 255)
    @NotNull
    private String password;

    @Column(name = "salt")
    @Size(max = 255)
    @NotNull
    private String salt;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getContact_number() {
        return contact_number;
    }

    public void setContact_number(String contact_number) {
        this.contact_number = contact_number;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
