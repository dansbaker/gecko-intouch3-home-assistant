# Gecko InTouch3 Home Assistant Integration

[![GitHub Release](https://img.shields.io/github/release/dansbaker/gecko-intouch3-home-assistant.svg?style=flat-square)](https://github.com/dansbaker/gecko-intouch3-home-assistant/releases)
[![GitHub License](https://img.shields.io/github/license/dansbaker/gecko-intouch3-home-assistant.svg?style=flat-square)](LICENSE)
[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-2023.1%2B-blue.svg?style=flat-square)](https://www.home-assistant.io/)

> **⚠️ Development Status: Alpha v0.0.1**
> 
> This code is not production ready. I'm sharing this repo in the hopes that other devs will contribute to testing and adding more features. I **strongly** recommend that you do not install this in HA unless you're a developer who understands how to debug home assistant integrations. Setting up the authentication alone requires you to intercept secure SSL connections being made from the Gecko app.

## 📦 Installation


1. Copy the entire `custom_components/gecko_spa` folder to your Home Assistant config directory:
   ```bash
   cp -r custom_components/gecko_spa /config/custom_components/
   ```

2. Restart Home Assistant

3. Add the integration through **Settings** → **Devices & Services** → **Add Integration** → Search for "Gecko Spa Controller"


## 🔑 Token Setup

The integration will prompt you to paste the OAuth JSON response during setup. 

## 🎛️ Available Entities

After installation, you'll have these entities:

- `climate.gecko_spa_temperature` - Temperature control (20°C - 40°C)
- `switch.gecko_spa_lights` - Lighting control  
- `switch.gecko_spa_pump_1` - Pump 1 control
- `switch.gecko_spa_pump_2` - Pump 2 control (if available)
- `switch.gecko_spa_pump_3` - Pump 3 control (if available)


## Setup & Configuration

### Step 1: Get Your OAuth Token

Since Gecko's API requires OAuth authentication, you'll need to intercept the login process to get your token. I recommend using Charles Proxy on iOS for this. Similar solutions probably exist for Android.

#### Using Charles Proxy on iOS

1. **Install Charles Proxy on iOS**
   - Download "Charles Proxy" from the App Store on your iPhone/iPad

2. **Configure Charles on iOS**
   - Open Charles Proxy app on your device
   - Tap **Start Recording** (if not already started)
   - Go to **Settings** (gear icon)
   - Enable **SSL Proxying**
   


3. **Install Charles Certificate**
   - In Charles settings, tap **SSL Proxying**
   - Tap **Install Charles Root Certificate**
   - Follow the iOS prompts to install the certificate
   - Go to **Settings** → **General** → **About** → **Certificate Trust Settings**
   - Enable full trust for the Charles Proxy CA certificate
   - Enable SSL proxying for the host `gecko-prod.us.auth0.com`

5. **Enable Charles Proxy**
   - In Charles app, ensure recording is started

6. **Login to Gecko App**
   - Open the official Gecko spa app on the same iPhone/iPad
   - Log out if already logged in
   - Log back in with your Gecko credentials
   - Charles will capture all network traffic

7. **Find the OAuth Token**
   - Switch back to Charles Proxy app
   - Look for requests to `gecko-prod.us.auth0.com`
   - Find the `/oauth/token` endpoint (tap to expand)
   - Tap on the **Response** section
   - Copy the entire JSON response body
   - It should look like:
     ```json
     {
       "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIs...",
       "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIs...",
       "scope": "openid profile email",
       "expires_in": 86400,
       "token_type": "Bearer"
     }
     ```

8. **Share the Token**
   - Use the **Share** button in Charles to email/copy the JSON response
   - You'll paste this into Home Assistant's configuration dialog


### Step 2: Add Integration to Home Assistant

1. **Go to Integrations**
   - Navigate to **Settings** → **Devices & Services**
   - Click **+ Add Integration**

2. **Search for Gecko**
   - Type "Gecko" in the search box
   - Select "Gecko InTouch3 Spa"

3. **Paste Token Response**
   - In the configuration dialog, paste the complete JSON response from Step 1
   - The integration will extract the necessary tokens automatically

4. **Complete Setup**
   - Click **Submit**
   - The integration will authenticate and discover your spa devices


### API Documentation

The integration uses Gecko's OAuth2 + AWS IoT MQTT pipeline:

1. **OAuth Authentication**: `gecko-prod.us.auth0.com`
2. **Account Discovery**: `/v3/accounts/{accountId}/vessels`
3. **Live Stream**: `/v2/monitors/{monitorId}/liveStream`
4. **MQTT Control**: AWS IoT shadow state updates

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This is an unofficial integration. Gecko, InTouch, and related trademarks are property of their respective owners.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/dansbaker/gecko-intouch3-home-assistant/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dansbaker/gecko-intouch3-home-assistant/discussions)
- **Home Assistant Community**: [Community Forum](https://community.home-assistant.io/)
