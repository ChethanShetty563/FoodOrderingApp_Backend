package com.upgrad.FoodOrderingApp.service.dao;

import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;

@Repository
public class CustomerDao {

    @PersistenceContext
    private EntityManager entityManager;

    public CustomerEntity customerSignup(final CustomerEntity customerEntity)
    {
        entityManager.persist(customerEntity);
        return customerEntity;
    }

    public CustomerEntity findByContactNumber(final String contactNumber)
    {
        try {
            CustomerEntity customerEntity = entityManager.createNamedQuery("findByContactNumber", CustomerEntity.class).setParameter("contactNumber", contactNumber).getSingleResult();
            return customerEntity;
        }catch (NoResultException nre) {
            return null;
        }
    }

    public CustomerEntity findByUuid(final String uuid)
    {
        try {
            CustomerEntity customerEntity = entityManager.createNamedQuery("findByUuid", CustomerEntity.class).setParameter("uuid", uuid).getSingleResult();
            return customerEntity;
        }catch (NoResultException nre) {
            return null;
        }

    }

    public CustomerEntity updateCustomer(final CustomerEntity customerEntity) {
        entityManager.merge(customerEntity);
        return customerEntity;
    }


}
