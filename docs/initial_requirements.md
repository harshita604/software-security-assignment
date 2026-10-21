# **Software Security Assignment** 

## **A) Requirements of the Application** 

A research workspace is to be built and following are the functional and nonfunctional requirements of the application: 

- **Functional Requirements** : 

These refer to the core requirements of the application (what it should do?) FR1: The application allows the users to login to their accounts. 

FR2: Users own datasets containing sensitive research information. 

FR3: Each user can create, update or delete their dataset. 

FR4: The user can format and export the dataset to their own system using an external package. 

FR5: Admin can see any user’s datasets 

FR6: Admin can delete any user’s datasets 

FR7: Admin can export any user datasets 

- **Non-Functional/Security Requirements** These are additional requirements to make sure the application is secure. 

SR1: Multi-tenant Isolation should be used to ensure that each user can only create, export or delete their own datasets. No user is allowed to access, modify or export another user’s sensitive data. 

SR2: Role-based authorization: Normal user and admin privileges are separate. The admin can access, delete and export any user data. 

SR3: The exported data must be only saved in a designated folder. They should not be overwritten anywhere else on the system. 

Mapping the functional and security requirements to three main functionalities of the system: 

|**Functionality**<br>_i  ii_|**Functional**<br>**Requirement**<br>**(FR)**|**Security**<br>**Requirement (SR)**|
|---|---|---|
|_Authorization and Authentication_: The user can<br>authenticate using pre-seeded login credentials,<br>to view and update their data. Normal user roles<br>are separate from admin privileges.|FR1, FR5, FR6,<br>FR7|SR1, SR2|
|_Dataset Management_: Users can create, read,<br>update or delete datasets. Users can perform<br>these only on their datasets and admins can<br>onlyview,delete or export datasets.<br>_tii_|FR2, FR3, FR5,<br>FR6|SR2, SR3|
|_Formatting and Exporting data_: The user|FR4,FR7|SR2,SR3|



datasets can be formatted in a specific manner and saved using an external package. 

### **Asset Register** 

|**S.No**|**Asset**|**Description/Purpose**|**Security Importance**|
|---|---|---|---|
|**.**||||
|A1|User Datasets|These are research<br>datasets the user<br>performs CRUD<br>operations on and can<br>contain sensitive data.|They contain<br>confidential user<br>data.|
|A2|User credentials|These are login<br>credentials (username<br>and password) needed<br>for the user to login.|Sensitive data, which<br>if exposed can allow<br>access to other<br>users’ data.|
|A3|Export Data|This is the data the user<br>exports using external<br>package|This is confidential<br>data, related to<br>specific user-owned<br>research datasets.|



### **STRIDE Modelling** 

|**STRIDE Category**|**Threat/Attack**|**Affected Asset**|**Impact**|
|---|---|---|---|
|Spoofing|**t**<br>Leaking of user<br>credentials, allowing<br>user impersonation|**f**<br>A1, A2, A3|Sensitive research<br>data of users is<br>exposed|
|Tampering|Tamper with user<br>specific research<br>data|A1, A2, A3|User-specific data<br>can be modified or<br>exported|
|Repudiation||||
|Information<br>Disclosure||||
|Denial of Service||||
|Elevation of Privilege|Normal user gets<br>admin privileges|A3, A2|User can exercise<br>admin privileges<br>impacting sensitive<br>data|



### **Access Control Matrix** 

|**Operation**|**User(own data)**|**User(other’s data)**|**Admin**|
|---|---|---|---|
|Creation of dataset|allow|deny|deny|
|i<br>Read dataset|allow|deny|allow|
|Update Dataset|allow|deny|deny|



|Delete data|allow|deny|allow|
|---|---|---|---|
|Export data|allow|deny|allow|



## **B) Implementation & Build** 

