# D-TECH API-Fier Proxy Server

This project is a Node.js-based proxy server capable of intercepting and logging HTTP and HTTPS traffic using a Man-In-The-Middle (MITM) approach.

## Directory Structure

Here is how the project files are structured and their purposes:

- `src/` - Contains the server's source code logic.
  - `server.js` - The main entry point. It sets up the Dashboard (port 3000), the Main Proxy Server (port 8082), and an Internal HTTPS MITM Server (port 8443) to intercept secure traffic.
  - `certUtils.js` - A utility module used to generate a Root Certificate Authority (Root CA) and fake certificates on-the-fly for intercepted HTTPS connections.
- `public/` - Contains static web assets.
  - `index.html` - The frontend for the Dashboard where you can view live traffic logs.
- `certs/` - This folder is automatically generated when you run the server for the first time. It contains your generated `rootCA.pem` and `rootCA.key` files used for MITM interception.
- `package.json` & `package-lock.json` - Node.js dependency configuration files.
- `README.md` - This file.

## How to Run on Your PC

To run this project on your local PC, follow these steps:

1. **Install Dependencies**
   Ensure you have Node.js installed on your system. Then, open your terminal (Command Prompt, PowerShell, or bash) in the project root directory and run:
   ```bash
   npm install
   ```

2. **Start the Server**
   To start the proxy server and dashboard, run:
   ```bash
   npm start
   ```

3. **Access the Dashboard**
   Open your web browser and navigate to `http://localhost:3000`. Here, you can monitor intercepted requests.

4. **Install the Root CA**
   For the server to successfully intercept HTTPS traffic without browsers showing security warnings, you need to download and install the D-TECH Root CA. You can do this by clicking the "[ DOWNLOAD ROOT CA ]" button on the Dashboard.

5. **Configure Your System or Browser Proxy**
   To route traffic through the proxy, configure your device or browser's proxy settings to use `localhost` (or `127.0.0.1`) on port `8082`.

## What is Irrelevant for Your Setup?

- If you strictly only want to view HTTP traffic, the `certs/` folder and `certUtils.js` logic for generating fake certificates might be overkill. However, since almost all modern web traffic is HTTPS, you will likely need it.
- If you run this exclusively on a local environment without external devices needing to connect, configuring the host mappings in `server.js` to `0.0.0.0` could be restricted to `127.0.0.1` for increased security.
