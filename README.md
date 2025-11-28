# Ecommerce Microservice

This project is a RESTful API for a ecommerce platform using the microservice architecture

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [License](#license)

## Features

- User Service - handle user registration, authentication, and profile management
- Product Catalog Service - manage product listings, categories, and inventory
- Shopping Cart Service - manage users' shopping carts, including adding/removing items and updating quantities
- Order Service - processes orders, including placing orders, tracking order status, managing order history
- Payment Service - handles payment processing, integrating with external payment gateways
- Notification Service - sends email and SMS notifications for various events

## Getting Started

- This project uses the microservice architecture (each service is an Express application)
- Contribute by creating issues and/or pull requests
- Create an .env file for each service and put environment variables inside that file
- See `package.json` for more project details such as script commands and dependencies

## API Documentation

This a [RESTful API](https://restfulapi.net/). It works only with JSON when accepting requests and returning responses. It also uses standard HTTP response codes, authentication, and verbs.

### Authentication & Authorization

This API uses - to authenticate clients and role-based access control (RBAC) to authorize clients on certain actions.

### Endpoints

#### User Service

| Endpoint     | Method | Description                            | Parameters                                  | Example Responses                                             |
| ------------ | ------ | -------------------------------------- | ------------------------------------------- | ------------------------------------------------------------- |
| /v1/register | POST   | Create an account                      | {"email" : "string", "password" : "string"} | {"id" : "string", "email" : "string", "createdAt" : "string"} |
| /v1/login    | POST   | Login and get a JWT for authentication | {"email" : "string", "password" : "string"} | {"token" : "string"}                                          |
| /v1/profile  | GET    | Get current user data                  |                                             | {"email" : "string"}                                          |

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT). See [LICENSE](https://github./com/project-name/blob/HEAD/LICENSE) for the full license text.
