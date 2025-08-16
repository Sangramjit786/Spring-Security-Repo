# Spring Security Comprehensive Guide

A comprehensive guide and implementation of Spring Security concepts, from basic authentication to advanced OAuth2 and OpenID Connect flows.

## Table of Contents

### 1. Getting Started
1. [Creating a Simple Spring Boot App](#1 creating a simple spring boot app)
2. [Securing Spring Boot with Basic Authentication](#2 securing spring boot basic app using spring security)

### 2. Core Security Concepts
3. [Understanding Security Fundamentals](#3 what is security  why it is important)
4. [Servlets & Filters](#4 quick introduction to servlets  filters)
5. [Spring Security Internal Flow](#5 introduction to spring security internal flow)
6. [Demo: Spring Security Internal Flow](#6 demo of spring security internal flow)
7. [Sequence Flow of Default Behavior](#7 sequence flow of the spring security default behaviour)

### Spring Security Internal Flow
<img width="1396" height="782" alt="image" src="https://github.com/user-attachments/assets/137b84b9-762f-473c-a6b8-3e9d51c60f46" />

### Spring Security Internal Flow For Default Behaviour
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/36649af7-d85a-4eee-ae44-17ce30b94b66" />

### 3. Authentication & Authorization
8. [Multiple Requests Without Credentials](#8 understanding on how multiple requests work with out credentials)
9. [EazyBank UI Overview](#9 understanding about ui part of the eazybank application)
10. [Backend Services Implementation](#10 creating backend services needed for the eazybank application)
11. [Default Security Configuration](#11 checking the default configuration inside the spring security framework)
12. [Custom Security Configuration](#12 modifying the security config code as per our custom requirements)

### 4. Authentication Methods
13. [Disabling Form Login & HTTP Basic](#13 how to disable formlogin and httpbasic authentication)
14. [HTTP Basic Authentication Testing](#14 httpbasic authentication testing using postman)
15. [In Memory Authentication](#15 configuring users using inmemoryuserdetailsmanager)
16. [Password Encoding](#16 configuring passwordencoder using passwordencoderfactories)
17. [Password Security](#17 demo of compromisedpasswordchecker)

### 5. User Management
18. [UserDetailsService & UserDetailsManager](#18 deep dive of userdetailsservice  userdetailsmanager interfaces)
19. [UserDetails & Authentication](#19 deep dive of userdetails  authentication interfaces)
20. [Enhancements Review](#20 quick revision of enhancements done so far)
21. [MySQL Database Setup with Docker](#21 creating mysql database using docker)
22. [JdbcUserDetailsManager](#22 understanding jdbcuserdetailsmanager  creating users inside the db)
23. [JdbcUserDetailsManager Authentication](#23 using jdbcuserdetailsmanager to perform authentication)

### 6. Custom Authentication
24. [Custom Tables for Authentication](#24 creating our own custom tables for authentication)
25. [JPA Entities & Repositories](#25 creating jpa entity and repository classes for new table)
26. [Custom UserDetailsService](#26 creating our own custom implementation of userdetailsservice)
27. [User Registration API](#27 building a new rest api to allow the registration of new user)

### 7. Password Security
28. [Password Validation](#28 how our passwords validated with out passwordencoders)
29. [Encoding & Decoding](#29 what is encoding decoding  why it is not suitable for passwords management)
30. [Encryption & Decryption](#30 what is encryption decryption  why it is not suitable for passwords management)
31. [Encryption Demo](#31 demo of encryption decryption)
32. [Hashing Introduction](#32 introduction to hashing)
33. [Hashing Drawbacks](#33 drawbacks of hashing  what are brute force attacks dictionary or rainbow tab)
34. [Securing Hashing](#34 how to overcome hashing drawbacks brute force and dictionary table attacks)
35. [PasswordEncoders in Spring](#35 introduction to passwordencoders in spring security)
36. [PasswordEncoder Implementations](#36 deep dive of passwordencoder implementation classes)
37. [Bcrypt Demo](#37 demo of registration and login with bcrypt password encoder)

### Encoding vs Encryption vs Hashing
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/93b6f94c-d91e-491b-a0b7-8c19ca1708f0" />

### 8. Custom Authentication Provider
38. [Custom AuthenticationProvider](#38 why should we consider creating our own authenticationprovider)
39. [AuthenticationProvider Methods](#39 understanding authenticationprovider methods)
40. [Custom AuthenticationProvider Implementation](#40 implementing and customizing the authenticationprovider inside our application)

### 9. Advanced Configuration
41. [Environment Specific Security](#41 environment specific security configurations using profiles)
42. [HTTPS Configuration](#42 accepting only https traffic using spring security)
43. [Exception Handling](#43 exception handling in spring security framework)
44. [Custom AuthenticationEntryPoint](#44 defining custom authenticationentrypoint)
45. [Custom AccessDeniedHandler](#45 defining custom accessdeniedhandler)

### 10. Session Management
46. [Session Timeout](#46 session timeout  invalid session configurations)
47. [Concurrent Session Control](#47 concurrent session control configurations)
48. [Session Fixation Protection](#48 session fixation attack protection with spring security)
49. [Authentication Events   Theory](#49 listening authentication events   theory)
50. [Authentication Events   Demo](#50 listening authentication events   demo)

### 11. Web Security
51. [Form Login Configuration](#51 form login configurations for mvc or monolithic apps)
52. [Logout Configuration](#52 logout configurations for mvc or monolithic apps)
53. [Thymeleaf Integration](#53 spring security thymeleaf integration)
54. [SecurityContext & SecurityContextHolder](#54 role of securitycontext  securitycontextholder)
55. [Loading User Details](#55 load login user details in spring security)

### 12. Frontend Integration
56. [Angular UI Setup](#56 setting up the eazybank ui project)
57. [Angular Code Walkthrough](#57 understanding and walkthrough of the angular code)
58. [Database Schema Update](#58 creating new db schema for eazybank scenarios)
59. [Backend Updates](#59 updating backend project based on the latest db schema)
60. [User Registration Testing](#60 testing registration of the new user with latest changes)

### 13. CORS & CSRF
61. [CORS Error](#61 taste of cors error)
62. [CORS Introduction](#62 introduction to cors)
63. [CORS Solutions](#63 possible options to fix the cors issue)
64. [CORS with Spring Security](#64 fixing cors issue using spring security)
65. [CSRF Protection](#65 demo of default csrf protection inside spring security)
66. [CSRF Attacks](#66 introduction to csrf attack)
67. [CSRF Protection Solutions](#67 solution to handle csrf attacks)
68. [CSRF Implementation   Backend](#68 implementing csrf token solution inside backend application)
69. [CSRF Implementation   Frontend](#69 implementing csrf token solution inside ui application)
70. [CSRF Exclusions](#70 ignoring csrf protection for public apis)

### 14. Authorization
71. [Authentication vs Authorization](#71 authentication vs authorization)

### Authentication vs Authorization
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/9bf63f0e-def0-4702-bf10-2d8834a2d4dc" />

72. [Storing Authorities](#72 how authorities stored inside spring security)
73. [Authorities Table](#73 creating new table authorities to store multiple roles or authorities)
74. [Loading Authorities from DB](#74 making backend changes to load authorities from new db table)
75. [Web Authorization](#75 configuring authorities inside web application using spring security)
76. [Authority vs Role](#76 authority vs role in spring security)
77. [Role Based Authorization](#77 configuring roles authorization inside web application using spring security)
78. [Authorization Events](#78 listening to the authorization events)

### 15. Custom Filters
79. [Inbuilt Filters](#79 demo of inbuilt filters of spring security framework)
80. [Custom Filter Creation](#80 how to create and configure our own custom filter)
81. [addFilterBefore()](#81 adding a custom filter using addfilterbefore method)
82. [addFilterAfter()](#82 adding a custom filter using addfilterafter method)
83. [addFilterAt()](#83 adding a custom filter using addfilterat method)

### Add Filter Before
<img width="1362" height="276" alt="image" src="https://github.com/user-attachments/assets/79bac3b2-12da-4c71-826e-05f958d9f917" />

### Add Filter After
<img width="1353" height="265" alt="image" src="https://github.com/user-attachments/assets/133f2715-d198-4290-a9aa-1e74df6aa337" />

### Add Filter At
<img width="1121" height="383" alt="image" src="https://github.com/user-attachments/assets/52b7dc9e-d69c-4a23-85c2-07d65addcbda" />

### 16. JWT Authentication
84. [Opaque vs JWT Tokens](#84 opaque tokens vs json web tokens jwt)
85. [Token-Based Authentication](#85 advantages of token based authentication)
86. [JWT Deep Dive](#86 deep dive about jwt tokens)
87. [JWT Configuration](#87 making project configuration to use jwt tokens)
88. [JWT Generation](#88 building logic to generate the jwt tokens)
89. [JWT Validation](#89 building logic to validate the jwt tokens)
90. [Client-Side JWT](#90 making changes on the client side for jwt token based authentication)
91. [JWT Testing](#91 validating the jwt changes made by running the applications)
92. [JWT Expiration](#92 validating the jwt token expiration scenario)
93. [Custom AuthenticationManager](#93 publish an authenticationmanager for custom or manual authentication)

### Roles Of Tokens
<img width="1372" height="447" alt="image" src="https://github.com/user-attachments/assets/70903546-049c-47a0-a611-4715287b8911" />

### JWT Tokens
<img width="1392" height="783" alt="image" src="https://github.com/user-attachments/assets/1b0c00fe-44b3-4d7e-9301-6ac00c7aed9e" />

### 17. Method Level Security
94. [Introduction](#94 introduction to method level security in spring security)
95. [Method Invocation Authorization](#95 details about method invocation authorization in method level security)
96. [@PreAuthorize & @PostAuthorize](#96 demo of method level security using preauthorize and postauthorize)
97. [Filtering Authorization](#97 details about filtering authorization in method level security)
98. [@PreFilter](#98 demo of prefilter annotation)
99. [@PostFilter](#99 demo of postfilter annotation)

### 18. OAuth2 & OpenID Connect
100. [OAuth2 Problem Statement](#100 problems that oauth2 trying to solve)
101. [OAuth2 Introduction](#101 introduction to oauth2)
102. [OAuth2 Terminologies](#102 oauth2 terminologies or jargons)
103. [OAuth2 Sample Flow](#103 demo of oauth2 sample flow)
104. [Authorization Code Flow](#104 deep dive on authorization code grant type flow in oauth2)
105. [Authorization Code Demo](#105 demo of authorization code grant type flow in oauth2)

### OAUTH2 Flow(Authorizatio Code)
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/c19b3774-761c-4594-84b3-5e9eeb9213b4" />

106. [Implicit Flow](#106 deep dive  demo of implicit grant flow in oauth2)
107. [PKCE Flow](#107 deep dive  demo of authorization code grant type with pkce)

### OAUTH2 Flow(PKCE)
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/57652446-0600-40ac-86dc-372edb791e33" />

108. [Password Grant](#108 deep dive of password grant type flow in oauth2)
109. [Client Credentials](#109 deep dive of client credentials grant type flow in oauth2)

### OAUTH2 Flow(Client Credentials Grant Type)
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/bff2f015-50e0-4934-a11f-744989d93ca5" />

110. [Refresh Token Flow](#110 deep dive of refresh token grant type flow in oauth2)

### OAUTH2 Flow(Refresh Token Grant Type)
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/6ac98ca3-e7d2-4793-87d4-0d345fba81dd" />

111. [Token Validation](#111 how resource server validates the tokens issued by auth server)
112. [OpenID Connect](#112 introduction to openid connect)

### 19. OAuth2 Implementation
113. [Implementation Overview](#113 introduction to the agenda of oauth2 implementations and demos)
114. [Social Logins](#114 demo of oauth2 using social logins)
115. [EazyBank OAuth2 Flow](#115 introduction to oauth2 flow inside eazybank web app)

### 20. Keycloak Integration
116. [Keycloak Introduction](#116 introduction to keycloak auth server)
117. [Keycloak Setup](#117 installation of keycloak server setup admin account  realm)
118. [Client Credentials in Keycloak](#118 creating client credentials inside keycloak for api api secured invocations)
119. [Resource Server Setup](#119 setup of eazybank resource server)
120. [Client Credentials Flow Demo](#120 client credentials grant type flow demo in eazybank)
121. [Opaque Tokens Demo](#121 demo of opaque tokens)
122. [Keycloak Client & User Setup](#122 creating client and user details inside keycloak for auth code grant flow)
123. [Auth Code & Refresh Token Demo](#123 testing authorization code  refresh grant types using postman app)
124. [PKCE Testing](#124 testing authorization code pkce grant types using postman app)
125. [Angular PKCE Implementation](#125 implementing pkce authorization code grant type inside angular ui app)
126. [PKCE Flow Testing](#126 testing pkce flow inside eazy bank angular ui application)
127. [MFA Configuration](#127 configuring mfa using keycloak)
128. [Social Login Integration](#128 social login integration with the help of keycloak)

### 21. Spring Authorization Server
129. [Spring Auth Server](#129 introduction to spring authorization server)
130. [Auth Server Setup](#130 set up of spring authorization server)
131. [Client Credentials Setup](#131 creating client credentials inside spring auth server for api api invocation)
132. [Client Credentials Demo](#132 client credentials grant type flow demo with spring auth server)
133. [Token Customization](#133 oauth2 token customization in spring auth server)
134. [Auth Code & PKCE Setup](#134 creating clients inside spring auth server for auth code  pkce grant type flows)
135. [Database Authentication](#135 updating spring auth server to authenticate the end user using db)
136. [Auth Code & PKCE Demo](#136 auth code  pkce grant type flows demo with spring auth server)
137. [Refresh Token Demo](#137 refresh token grant type flow demo with spring auth server)
138. [Opaque Tokens Demo](#138 demo of opaque tokens with spring auth server)


## 🚀 Prerequisites

- Java 21
- Maven 3.5+
- MySQL 8.0+
- Keycloak (for OAuth2/OpenID Connect)
- Docker (optional, for containerized services)

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone [https://github.com/Sangramjit786/Spring-Security-Repo.git](https://github.com/Sangramjit786/Spring-Security-Repo.git)
   cd Spring-Security-Repo

## 🔧 Configuration
## Database Configuration
- Update src/main/resources/application.properties:

  ```
  spring.datasource.url=jdbc:mysql://localhost:3306/your_database
  spring.datasource.username=your_username
  spring.datasource.password=your_password
  spring.jpa.hibernate.ddl-auto=update

## Keycloak Configuration:

- To enable OAuth2 with Keycloak, update the following properties:

  ```
  spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8180/realms/your-realm
  spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:8180/realms/your-realm/protocol/openid-connect/certs

## Project Structure

- The project follows a standard Spring Boot project structure:

   ```
   src/main/java/com/eazybytes/
   ├── config/           # Security and application configurations\n
   ├── constants/        # Application constants
   ├── controller/       # REST controllers
   ├── events/           # Application events
   ├── exceptionhandling/ # Exception handlers
   ├── filter/           # Custom security filters
   ├── model/            # Entity classes
   └── repository/       # Data access layer

## Build the project:
mvn clean install

## Run the application:
mvn spring-boot:run

## Run tests using:
mvn test

## 🔐 Security Implementation**

## JWT Authentication:
  1. JWT token generation and validation
  2. Custom JWT filter
  3. Token expiration and refresh mechanism
  
## OAuth2 with Keycloak:
  1. OAuth2 Resource Server configuration
  2. Role-based access control
  3. Custom token mappers
  
## Method Security:
  1. @PreAuthorize and @PostAuthorize annotations
  2. Custom security expressions
  3. Method-level permission checks
  

## 🌐 API Endpoints**

## Secured Endpoints:
1. GET /myAccount - Get account details (requires USER role)
2. GET /myBalance - Get balance (requires USER role)
3. GET /myLoans - Get loan details (requires USER role)
4. GET /myCards - Get card details (requires ADMIN role)


## 🛡️Security Best Practices** 

## Password Security:
  1. BCrypt password hashing
  2. Password strength validation
  3. Secure password storage
  
## Session Management:
  1. Secure session configuration
  2. Session fixation protection
  3. Concurrent session control
  
## HTTPS:
  1. Enforce HTTPS
  2. Secure cookie configuration
  3. HSTS header
  
  
## 🙏 Acknowledgments:
  1. Spring Security Team
  2. Keycloak Community
  3. All open-source contributors

