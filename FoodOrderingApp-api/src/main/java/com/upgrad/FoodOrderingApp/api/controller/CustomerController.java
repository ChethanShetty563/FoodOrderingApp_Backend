package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.api.model.*;
import com.upgrad.FoodOrderingApp.service.businness.CustomerService;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import com.upgrad.FoodOrderingApp.service.exception.UpdateCustomerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.UUID;

@RestController
@RequestMapping("/")
public class CustomerController {

    @Autowired
    private CustomerService customerService;


    @CrossOrigin
    @RequestMapping(
            method = RequestMethod.POST,
            path = "/customer/signup",
            consumes = MediaType.APPLICATION_JSON_UTF8_VALUE,
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<SignupCustomerResponse> signup(
            @RequestBody(required = false) final SignupCustomerRequest signupCustomerRequest)
            throws SignUpRestrictedException {
        final CustomerEntity customerEntity = new CustomerEntity();
        customerEntity.setUuid(UUID.randomUUID().toString());
        customerEntity.setFirstName(signupCustomerRequest.getFirstName());
        customerEntity.setLastName(signupCustomerRequest.getLastName());
        customerEntity.setEmail(signupCustomerRequest.getEmailAddress());
        customerEntity.setPassword(signupCustomerRequest.getPassword());
        customerEntity.setContactnumber(signupCustomerRequest.getContactNumber());

        isValidSignupRequest(customerEntity);

        final CustomerEntity createdCustomerEntity = customerService.saveCustomer(customerEntity);

        SignupCustomerResponse customerResponse =
                new SignupCustomerResponse()
                        .id(createdCustomerEntity.getUuid())
                        .status("CUSTOMER SUCCESSFULLY REGISTERED");
        return new ResponseEntity<SignupCustomerResponse>(customerResponse, HttpStatus.CREATED);
    }


    @CrossOrigin
    @RequestMapping(method = RequestMethod.POST,
            path = "/customer/login",
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<LoginResponse> login(@RequestHeader("authorization") final String authorization)
            throws AuthenticationFailedException {


        isValidAuthorizationFormat(authorization);


        byte[] decoded = Base64.getDecoder().decode(authorization.split("Basic ")[1]);
        String decodedAuth = new String(decoded);
        String[] decodedArray = decodedAuth.split(":");


        CustomerAuthEntity customerAuthEntity = customerService.authenticate(decodedArray[0], decodedArray[1]);
        CustomerEntity customer = customerAuthEntity.getCustomer();

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setId(customer.getUuid());
        loginResponse.setFirstName(customer.getFirstName());
        loginResponse.setLastName(customer.getLastName());
        loginResponse.setEmailAddress(customer.getEmail());
        loginResponse.setContactNumber(customer.getContactnumber());
        loginResponse.setMessage("LOGGED IN SUCCESSFULLY");

        HttpHeaders headers = new HttpHeaders();
        headers.add("access-token", customerAuthEntity.getAccessToken());
        headers.add("access-control-expose-headers", "access-token");
        return new ResponseEntity<LoginResponse>(loginResponse, headers, HttpStatus.OK);
    }


    @CrossOrigin
    @RequestMapping(method = RequestMethod.POST,
            path = "/customer/logout",
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<LogoutResponse> logout(@RequestHeader("authorization") final String authorization)
            throws AuthorizationFailedException {
        String accessToken = authorization.split("Bearer ")[1];
        CustomerAuthEntity customerAuthEntity = customerService.logout(accessToken);

        LogoutResponse logoutResponse = new LogoutResponse()
                .id(customerAuthEntity.getCustomer().getUuid()).message("LOGGED OUT SUCCESSFULLY");

        return new ResponseEntity<LogoutResponse>(logoutResponse, null, HttpStatus.OK);
    }


    @CrossOrigin
    @RequestMapping(method = RequestMethod.PUT,
            path = "/customer",
            consumes = MediaType.APPLICATION_JSON_UTF8_VALUE,
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<UpdateCustomerResponse> update(
            @RequestHeader("authorization") final String authorization,
            @RequestBody(required = false) UpdateCustomerRequest updateCustomerRequest)
            throws UpdateCustomerException, AuthorizationFailedException {

        isValidUpdateCustomerRequest(updateCustomerRequest.getFirstName());


        String accessToken = authorization.split("Bearer ")[1];
        CustomerEntity customerEntityToBeUpdated = customerService.getCustomer(accessToken);

        customerEntityToBeUpdated.setFirstName(updateCustomerRequest.getFirstName());
        customerEntityToBeUpdated.setLastName(updateCustomerRequest.getLastName());

        CustomerEntity updatedCustomerEntity = customerService.updateCustomer(customerEntityToBeUpdated);

        UpdateCustomerResponse updateCustomerResponse = new UpdateCustomerResponse();
        updateCustomerResponse.setFirstName(updatedCustomerEntity.getFirstName());
        updateCustomerResponse.setLastName(updatedCustomerEntity.getLastName());
        updateCustomerResponse.setId(updatedCustomerEntity.getUuid());
        updateCustomerResponse.status("CUSTOMER DETAILS UPDATED SUCCESSFULLY");

        return new ResponseEntity<UpdateCustomerResponse>(updateCustomerResponse, null, HttpStatus.OK);
    }


    @CrossOrigin
    @RequestMapping(method = RequestMethod.PUT,
            path = "/customer/password",
            consumes = MediaType.APPLICATION_JSON_UTF8_VALUE,
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<UpdateCustomerResponse> changePassword(
            @RequestHeader("authorization") final String authorization,
            @RequestBody(required = false) UpdatePasswordRequest updatePasswordRequest)
            throws AuthorizationFailedException, UpdateCustomerException {

        String oldPassword = updatePasswordRequest.getOldPassword();
        String newPassword = updatePasswordRequest.getNewPassword();

        if (oldPassword == null || oldPassword == "") {
            throw new UpdateCustomerException("UCR-003", "No field should be empty");
        }
        if (newPassword == null || newPassword == "") {
            throw new UpdateCustomerException("UCR-003", "No field should be empty");
        }


        String accessToken = authorization.split("Bearer ")[1];
        CustomerEntity customerEntityToBeUpdated = customerService.getCustomer(accessToken);

        CustomerEntity customerEntity = customerService.updateCustomerPassword(
                oldPassword,
                newPassword,
                customerEntityToBeUpdated
        );

        UpdateCustomerResponse updateCustomerResponse = new UpdateCustomerResponse();
        updateCustomerResponse.setFirstName(customerEntity.getFirstName());
        updateCustomerResponse.setLastName(customerEntity.getLastName());
        updateCustomerResponse.setId(customerEntity.getUuid());
        updateCustomerResponse.status("CUSTOMER PASSWORD UPDATED SUCCESSFULLY");

        return new ResponseEntity<UpdateCustomerResponse>(updateCustomerResponse, null, HttpStatus.OK);
    }


    private boolean isValidAuthorizationFormat(String authorization) throws AuthenticationFailedException {
        try {
            byte[] decoded = Base64.getDecoder().decode(authorization.split("Basic ")[1]);
            String decodedAuth = new String(decoded);
            String[] decodedArray = decodedAuth.split(":");
            String username = decodedArray[0];
            String password = decodedArray[1];
            return true;
        } catch (ArrayIndexOutOfBoundsException exc) {
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        }
    }


    private boolean isValidUpdateCustomerRequest(String firstName) throws UpdateCustomerException {
        if (firstName == null || firstName == "") {
            throw new UpdateCustomerException("UCR-002", "First name field should not be empty");
        }
        return true;
    }


    private boolean isValidSignupRequest(CustomerEntity customerEntity)
            throws SignUpRestrictedException {
        if (customerEntity.getFirstName() == null || customerEntity.getFirstName() == "") {
            throw new SignUpRestrictedException("SGR-005",
                    "Except last name all fields should be filled");
        }
        if (customerEntity.getPassword() == null || customerEntity.getPassword() == "") {
            throw new SignUpRestrictedException("SGR-005",
                    "Except last name all fields should be filled");
        }
        if (customerEntity.getEmail() == null || customerEntity.getEmail() == "") {
            throw new SignUpRestrictedException("SGR-005",
                    "Except last name all fields should be filled");
        }
        if (customerEntity.getContactnumber() == null || customerEntity.getContactnumber() == "") {
            throw new SignUpRestrictedException("SGR-005",
                    "Except last name all fields should be filled");
        }
        return true;
    }
}