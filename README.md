# vermicelli (U/C)

### Simple self-hosted version control automation application track and manage the versions of your applications.

***TBD***

## **update.sh - Documentation and Guide**

### **1. Description**
The **update.sh** script is designed to automate version updates for an application managed by a remote API. It follows these steps:

1. Authenticates with the specified service by sending a username and password to the **login** endpoint.  
2. Retrieves a JWT token from the response.  
3. Uses that token to call the **update_version** endpoint, incrementing the specified version part (**MAJOR**, **MINOR**, or **PATCH**).  
4. Outputs the new version if the update is successful.

This script makes it easy to manage and bump version numbers in your CI/CD pipelines or as part of a local development process.

---

### **2. Default Values**

- **DEFAULT_BASE_URL**: `http://localhost:8000`  
  The default URL of the API service. If you don’t provide a `--url` flag, the script will attempt to connect to this local address.

- **DEFAULT_USERNAME**: `admin`  
  The default username used for login. Adjust it if your service has different login credentials.

- **DEFAULT_PASSWORD**: `password`  
  The default password used for login. Change this to maintain security in a real environment.

- **DEFAULT_APP_ID**: `1`  
  The default application ID for which the version will be updated.

If you don’t supply overrides via flags, the script will use these default values.

---

### **3. Script Flags Explained**

1. **`--appid`**  
   - **Purpose**: Sets the application ID you want to update.  
   - **Default**: `1` (as per `DEFAULT_APP_ID`).

2. **`--version`**  
   - **Purpose**: **Required flag**. Defines which part of the version to update—`major`, `minor`, or `patch`.  
   - **Example**: `--version patch`  
   - **Note**: If `--version` is not provided, the script will exit with an error message.

3. **`--username`**  
   - **Purpose**: Specifies the username for login.  
   - **Default**: `admin` (as per `DEFAULT_USERNAME`).

4. **`--password`**  
   - **Purpose**: Specifies the password for login.  
   - **Default**: `password` (as per `DEFAULT_PASSWORD`).

5. **`--url`**  
   - **Purpose**: The base URL of your server or API endpoint.  
   - **Default**: `http://localhost:8000` (as per `DEFAULT_BASE_URL`).

---

### **4. Usage Example**

```bash
./update.sh --version patch --appid 10 --username myuser --password mypass --url http://myapi.example.com
