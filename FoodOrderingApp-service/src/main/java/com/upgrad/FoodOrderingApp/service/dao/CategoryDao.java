package com.upgrad.FoodOrderingApp.service.dao;

import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
import com.upgrad.FoodOrderingApp.service.entity.RestaurantEntity;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import java.util.List;


@Repository
public class CategoryDao {

    @PersistenceContext
    private EntityManager entityManager;

    //To get list categories  from the db if no result it returns null.

    public List<CategoryEntity> getAllCategories(){
        try {
            List<CategoryEntity> categoryEntities = entityManager.createNamedQuery("getAllCategoriesOrderedByName",CategoryEntity.class).getResultList();
            return categoryEntities;
        }catch (NoResultException nre){
            return null;
        }
    }

    public CategoryEntity getCategoryById(final String categryId)
    {
        try {
            CategoryEntity categoryEntity = entityManager.createNamedQuery("getCategoryByUuid",CategoryEntity.class).setParameter("categoryUuid",categryId).getSingleResult();
            return categoryEntity;
        }catch (NoResultException nre){
            return null;
        }
    }

   /* public List<CategoryEntity> getCategoriesByRestaurant(RestaurantEntity restaurantEntity)
    {
        return null;
    }*/
}