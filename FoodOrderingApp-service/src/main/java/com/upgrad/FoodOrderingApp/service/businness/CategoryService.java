package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CategoryDao;
import com.upgrad.FoodOrderingApp.service.dao.RestaurantDao;
import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
import com.upgrad.FoodOrderingApp.service.entity.RestaurantEntity;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CategoryService {

    @Autowired
    CategoryDao categoryDao;

    @Autowired
    RestaurantDao restaurantDao;


    public List<CategoryEntity> getAllCategoriesOrderedByName() {
        return categoryDao.getAllCategories();
    }


    public CategoryEntity getCategoryById(final String categoryUuid)
            throws CategoryNotFoundException {
        if(categoryUuid == null) {
            throw new CategoryNotFoundException("CNF-001", "Category id field should not be empty");
        }
        CategoryEntity categoryEntity = categoryDao.getCategoryById(categoryUuid);
        if(categoryEntity == null) {
            throw new CategoryNotFoundException( "CNF-002", "No category by this id");
        }
        return categoryEntity;
    }


    public List<CategoryEntity> getCategoriesByRestaurant(String restaurantId){
        RestaurantEntity restaurantEntity = restaurantDao.getRestaurantByUuid(restaurantId);
        return restaurantEntity.getCategories();
    }

}