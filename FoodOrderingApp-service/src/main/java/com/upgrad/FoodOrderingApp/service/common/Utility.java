package com.upgrad.FoodOrderingApp.service.common;

import java.util.*;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.*;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class Utility {

    public boolean isValidContact(String contactNumber){
        Pattern p = Pattern.compile("(0/91)?[7-9][0-9]{9}");
        Matcher m = p.matcher(contactNumber);
        return (m.find() && m.group().equals(contactNumber));
    }

    public boolean isValidEmail(String email) {
        String regex = "^[\\w-_\\.+]*[\\w-_\\.]\\@([\\w]+\\.)+[\\w]+[\\w]$";
        return email.matches(regex);
    }

    public boolean isValidPassword(String password){
        Boolean lowerCase = false;
        Boolean upperCase = false;
        Boolean number = false;
        Boolean specialCharacters = false;

        if(password.length() < 8){
            return false;
        }

        if(password.matches("(?=.*[0-9]).*")){
            number = true;
        }

        if(password.matches("(?=.*[a-z]).*")){
            lowerCase = true;
        }
        if(password.matches("(?=.*[A-Z]).*")){
            upperCase = true;
        }
        if(password.matches("(?=.*[#@$%&*!^]).*")){
            specialCharacters = true;
        }

        if(lowerCase && upperCase){
            if(specialCharacters && number){
                return true;
            }
        }else{
            return false;
        }
        return false;
    }

    public boolean isValidSignupRequest (CustomerEntity customerEntity)throws SignUpRestrictedException {
        if (customerEntity.getFirstname() == null || customerEntity.getFirstname() == ""){
            throw new SignUpRestrictedException("SGR-005","Except last name all fields should be filled");
        }
        if(customerEntity.getPassword() == null||customerEntity.getPassword() == ""){
            throw new SignUpRestrictedException("SGR-005","Except last name all fields should be filled");
        }
        if (customerEntity.getEmail() == null||customerEntity.getEmail() == ""){
            throw new SignUpRestrictedException("SGR-005","Except last name all fields should be filled");
        }
        if (customerEntity.getContact_number() == null||customerEntity.getContact_number() == ""){
            throw new SignUpRestrictedException("SGR-005","Except last name all fields should be filled");
        }
        return true;
    }

    public boolean isValidAuthorizationFormat(String authorization)throws AuthenticationFailedException {
        try {
            byte[] decoded = Base64.getDecoder().decode(authorization.split("Basic ")[1]);
            String decodedAuth = new String(decoded);
            String[] decodedArray = decodedAuth.split(":");
            String username = decodedArray[0];
            String password = decodedArray[1];
            return true;
        }catch (ArrayIndexOutOfBoundsException exc){
            throw new AuthenticationFailedException("ATH-003","Incorrect format of decoded customer name and password");
        }
    }

    public boolean isValidUpdatePasswordRequest(String oldPassword,String newPassword) throws UpdateCustomerException{
        if (oldPassword == null || oldPassword == "") {
            throw new UpdateCustomerException("UCR-003", "No field should be empty");
        }
        if (newPassword == null || newPassword == "") {
            throw new UpdateCustomerException("UCR-003", "No field should be empty");
        }
        return true;
    }

    public boolean isValidCustomerRequest (String firstName)throws UpdateCustomerException {
        if (firstName == null || firstName == "") {
            throw new UpdateCustomerException("UCR-002", "First name field should not be empty");
        }
        return true;
    }

}
