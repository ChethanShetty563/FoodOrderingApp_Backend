package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.api.model.*;
import com.upgrad.FoodOrderingApp.service.businness.CategoryService;
import com.upgrad.FoodOrderingApp.service.businness.CustomerService;
import com.upgrad.FoodOrderingApp.service.businness.ItemService;
import com.upgrad.FoodOrderingApp.service.businness.RestaurantService;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.InvalidRatingException;
import com.upgrad.FoodOrderingApp.service.exception.RestaurantNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;



@RestController
@RequestMapping("/")
public class RestaurantController {

    @Autowired
    CategoryService categoryService;

    @Autowired
    RestaurantService restaurantService;

    @Autowired
    ItemService itemService;

    @Autowired
    CustomerService customerService;


    @CrossOrigin
    @RequestMapping(method = RequestMethod.GET,
            value = "/restaurant",
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantListResponse> getAllRestaurants() {
        List<RestaurantEntity> restaurants = restaurantService.restaurantsByRating();
        return getRestaurantListResponseEntity(restaurants);
    }


    @CrossOrigin
    @RequestMapping(method = RequestMethod.GET,
            value = "/restaurant/name/{restaurant_name}",
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantListResponse> getRestaurantsByName(@PathVariable("restaurant_name") final String restaurantName)
            throws RestaurantNotFoundException {
        List<RestaurantEntity> restaurants = restaurantService.restaurantsByName(restaurantName);
        return getRestaurantListResponseEntity(restaurants);
    }

    @CrossOrigin
    @RequestMapping(method = RequestMethod.GET,
            value = "/restaurant/category/{category_id}",
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantListResponse> restaurantByCategory(@PathVariable("category_id") final String categoryId)
            throws CategoryNotFoundException {
        List<RestaurantEntity> restaurants = restaurantService.restaurantByCategory(categoryId);
        return getRestaurantListResponseEntity(restaurants);
    }


    @CrossOrigin
    @RequestMapping(method = RequestMethod.GET,
            value = "/restaurant/{restaurant_id}",
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantDetailsResponse> getRestaurantByUuid(@PathVariable("restaurant_id") final String restaurantId)
            throws RestaurantNotFoundException {
        RestaurantEntity restaurantEntity = restaurantService.restaurantByUUID(restaurantId);

        RestaurantDetailsResponse restaurantDetails = populateRestaurantDetailsObject(restaurantEntity);
        List<CategoryList> categoriesList = new ArrayList<>();
        List<CategoryEntity> categoriesByRestaurant = categoryService.getCategoriesByRestaurant(restaurantId);
        for (CategoryEntity categoryEntity : categoriesByRestaurant) {
            CategoryList categoryList = new CategoryList();
            UUID uuid = UUID.fromString(categoryEntity.getUuid());
            categoryList.setId(uuid);
            categoryList.setCategoryName(categoryEntity.getCategoryName());
            List<ItemEntity> itemEntities = itemService.getItemsByCategoryAndRestaurant(restaurantId, categoryEntity.getUuid());
            final List<ItemList> itemLists = new ArrayList<>();
            for (ItemEntity item : itemEntities) {
                populateItemListObject(itemLists, item);
            }
            categoryList.setItemList(itemLists);
            categoriesList.add(categoryList);
        }
        restaurantDetails.setCategories(categoriesList);
        return new ResponseEntity<RestaurantDetailsResponse>(restaurantDetails, HttpStatus.OK);
    }


    @CrossOrigin
    @RequestMapping(method = RequestMethod.PUT,
            path = "/restaurant/{restaurant_id}",
            params = "customer_rating",
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<RestaurantUpdatedResponse> updateRestaurantDetails(@RequestHeader("authorization") final String authorization,
                                                                             @PathVariable(value = "restaurant_id") final String restaurantUuid,
                                                                             @RequestParam(value = "customer_rating") final Double customerRating)
            throws AuthorizationFailedException, RestaurantNotFoundException, InvalidRatingException {

        String accessToken = authorization.split("Bearer ")[1];
        customerService.getCustomer(accessToken);

        RestaurantEntity restaurantEntity = restaurantService.restaurantByUUID(restaurantUuid);
        RestaurantEntity updatedRestaurantEntity = restaurantService.updateRestaurantRating(restaurantEntity, customerRating);
        RestaurantUpdatedResponse restaurantUpdatedResponse = new RestaurantUpdatedResponse();
        restaurantUpdatedResponse.setId(UUID.fromString(restaurantUuid));
        restaurantUpdatedResponse.setStatus("RESTAURANT RATING UPDATED SUCCESSFULLY");

        return new ResponseEntity<RestaurantUpdatedResponse>(restaurantUpdatedResponse, HttpStatus.OK);
    }


    private ResponseEntity<RestaurantListResponse> getRestaurantListResponseEntity(List<RestaurantEntity> restaurants) {
        List<RestaurantList> restaurantLists = new ArrayList<>();
        RestaurantListResponse restaurantListResponse = new RestaurantListResponse();
        for (RestaurantEntity restaurantEntity : restaurants) {
            RestaurantList restaurant = populateRestaurantListObject(restaurantEntity);
            //Get Category names of that restaurant
            List<CategoryEntity> categoriesList = categoryService.getCategoriesByRestaurant(restaurantEntity.getUuid());
            restaurant.setCategories(getCommaSeparatedCategoryName(categoriesList));
            restaurantLists.add(restaurant);
        }
        restaurantListResponse.restaurants(restaurantLists);
        return new ResponseEntity<RestaurantListResponse>(restaurantListResponse, HttpStatus.OK);
    }


    static void populateItemListObject(List<ItemList> itemLists, ItemEntity item) {
        ItemList itemList = new ItemList();
        UUID itemUuid = UUID.fromString(item.getUuid());
        itemList.setId(itemUuid);
        itemList.setItemName(item.getItemName());
        itemList.setPrice(item.getPrice());
        itemList.setItemType(ItemList.ItemTypeEnum.fromValue(item.getType().getValue()));
        itemLists.add(itemList);
    }


    private RestaurantList populateRestaurantListObject(RestaurantEntity restaurantEntity) {
        RestaurantList restaurant = new RestaurantList()
                .id(UUID.fromString(restaurantEntity.getUuid()))
                .restaurantName(restaurantEntity.getRestaurantName())
                .photoURL(restaurantEntity.getPhotoUrl())
                .customerRating(getConvertedRating(restaurantEntity.getCustomerRating()))
                .averagePrice(restaurantEntity.getAvgPrice())
                .numberCustomersRated(restaurantEntity.getNumberCustomersRated());

        RestaurantDetailsResponseAddress restaurantDetailsResponseAddress = populateAddressObject(restaurantEntity.getAddress());
        restaurant.setAddress(restaurantDetailsResponseAddress);
        return restaurant;
    }

    private RestaurantDetailsResponse populateRestaurantDetailsObject(RestaurantEntity restaurantEntity) {
        RestaurantDetailsResponse restaurantDetails = new RestaurantDetailsResponse()
                .id(UUID.fromString(restaurantEntity.getUuid()))
                .restaurantName(restaurantEntity.getRestaurantName())
                .photoURL(restaurantEntity.getPhotoUrl())
                .customerRating(getConvertedRating(restaurantEntity.getCustomerRating()))
                .averagePrice(restaurantEntity.getAvgPrice())
                .numberCustomersRated(restaurantEntity.getNumberCustomersRated());

        RestaurantDetailsResponseAddress restaurantDetailsResponseAddress = populateAddressObject(restaurantEntity.getAddress());
        restaurantDetails.setAddress(restaurantDetailsResponseAddress);
        return restaurantDetails;
    }


    private RestaurantDetailsResponseAddress populateAddressObject(AddressEntity addressEntity) {
        StateEntity stateEntity = addressEntity.getState();
        RestaurantDetailsResponseAddressState restaurantDetailsResponseAddressState = new RestaurantDetailsResponseAddressState()
                .stateName(stateEntity.getStateName())
                .id(UUID.fromString(stateEntity.getUuid()));
        RestaurantDetailsResponseAddress restaurantDetailsResponseAddress = new RestaurantDetailsResponseAddress()
                .id(UUID.fromString(addressEntity.getUuid()))
                .flatBuildingName(addressEntity.getFlatBuilNumber())
                .locality(addressEntity.getLocality())
                .city(addressEntity.getCity())
                .pincode(addressEntity.getPincode())
                .state(restaurantDetailsResponseAddressState);
        return restaurantDetailsResponseAddress;
    }


    private String getCommaSeparatedCategoryName(List<CategoryEntity> categoriesList) {
        List<String> categoryNames = new ArrayList<>();
        categoriesList.forEach(categoryEntity -> {
            categoryNames.add(categoryEntity.getCategoryName());
        });
        return String.join(", ", categoryNames);
    }


    private BigDecimal getConvertedRating(double rating) {
        BigDecimal ratingInBigDecimal = BigDecimal.valueOf(rating);
        ratingInBigDecimal = ratingInBigDecimal.setScale(1, BigDecimal.ROUND_UP);
        return ratingInBigDecimal;
    }
}