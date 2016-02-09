Restfull Toboggan
====================
Restful Toboggan enable authentication by email or username on Drupal 7, require RESTful-Drupal module ( Restful Best Practice )

## Requirements
Drupal 7.4

##Dependencies 
RESTful-Drupal https://github.com/RESTful-Drupal/restful

## Resource Url 
{base_url}/api/login-toboggan 

return X-CSRF-Token

## Angularjs Client
You can use Gizra/angular-restful-auth  as client, change the url parameter at the line 100 of
https://github.com/Gizra/angular-restful-auth/blob/master/app/scripts/services/userlogin.js
form /api/login to /api/login-toboggan

## Credit
[Riccardo Ravaro](http://riccardoravaro.com)
