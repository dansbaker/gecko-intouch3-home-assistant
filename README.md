# Gecko InTouch3 Home Assistant Integration

[![GitHub Release](https://img.shields.io/github/release/dansbaker/gecko-intouch3-home-assistant.svg?style=flat-square)](https://github.com/dansbaker/gecko-intouch3-home-assistant/releases)
[![GitHub License](https://img.shields.io/github/license/dansbaker/gecko-intouch3-home-assistant.svg?style=flat-square)](LICENSE)
[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-2023.1%2B-blue.svg?style=flat-square)](https://www.home-assistant.io/)

A Home Assistant integration for Gecko InTouch3 spa controllers. Control your hot tub temperature, lights, and pumps directly from Home Assistant.

## Installation

### Option 1: HACS (Recommended)

1. Install [HACS](https://hacs.xyz/) if you haven't already
2. In the HACS panel, go to "Integrations"
3. Click the three dots in the top right corner and select "Custom repositories"
4. Add this repository URL: `https://github.com/dansbaker/gecko-intouch3-home-assistant`
5. Select "Integration" as the category
6. Click "Add"
7. Find "Gecko Spa Controller" in the list and click "Download"
8. Restart Home Assistant

### Option 2: Manual Installation

1. Copy the integration files to your Home Assistant:
   ```bash
   cp -r custom_components/gecko_spa /config/custom_components/
   ```
2. Restart Home Assistant

## Setup

1. Go to **Settings** → **Devices & Services** → **Add Integration**
2. Search for "Gecko Spa Controller"
3. Enter your Gecko Connect username and password when prompted

The integration will automatically authenticate and discover your hot tub.

## Available Controls

- **Climate**: Set target temperature (20°C - 40°C)
- **Lights**: Turn spa lights on/off  
- **Pumps**: Control jets and circulation pumps

## Troubleshooting

### Debug Tool for Issue Reporting

If you're experiencing issues with the integration, please use the included debug tool to generate a comprehensive debug report. This tool collects all necessary information while automatically redacting personal information (email, account IDs, location data, etc.).

**To generate a debug report:**

1. Navigate to the repository directory:
   ```bash
   cd /path/to/gecko-hot-tub-control
   ```

2. Run the debug tool:
   ```bash
   ./venv/bin/python gecko_debug_tool.py --username your@email.com --duration 60
   ```
   
   You'll be prompted for your password. The tool will:
   - Authenticate with your Gecko account
   - Retrieve spa configuration
   - Connect to MQTT and capture messages
   - Save everything to a timestamped JSON file (e.g., `gecko_debug_20251011_185723.json`)

3. When reporting issues on GitHub, **please attach this debug file**. It contains:
   - Spa configuration (pumps, lights, waterfalls, blowers, zones)
   - MQTT message samples
   - Authentication status
   - All personal information is automatically redacted for privacy

**Tool Options:**
- `--username` or `-u`: Your Gecko account email (required)
- `--password` or `-p`: Your password (will prompt if not provided)
- `--duration` or `-d`: How many seconds to monitor MQTT (default: 30)
- `--output` or `-o`: Custom output filename
- `--verbose` or `-v`: Enable verbose debug logging

**Example:**
```bash
./venv/bin/python gecko_debug_tool.py -u your@email.com -d 60 -o my_debug.json
```

The debug file is safe to share publicly as it redacts:
- Email addresses and usernames
- Account IDs, vessel IDs, and monitor IDs
- Physical location data (addresses, coordinates, timezones)
- Google Maps URLs with GPS coordinates
- AWS IoT credentials and broker URLs
- All names and personal identifiers

### Enable Debug Logging

To get detailed logs including MQTT payloads, add this to your `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.gecko_spa: debug
```

After saving, restart Home Assistant. With debug logging enabled, you'll see:
- Full MQTT payloads received from your spa
- Outgoing commands sent to your spa  
- Authentication and connection details
- Detailed error information

View the logs in **Settings** → **System** → **Logs** or check the Home Assistant log file.

### Common Issues

- **Authentication Failed**: Verify your Gecko Connect username and password
- **Connection Timeout**: Check your internet connection and spa's Wi-Fi
- **No Entities**: The spa may take a few minutes to appear after setup


## License

MIT License - see LICENSE file for details.

This is an unofficial integration. Gecko and InTouch are trademarks of their respective owners.
# Gecko InTouch3 Home Assistant Integration

[![GitHub Release](https://img.shields.io/github/release/dansbaker/gecko-intouch3-home-assistant.svg?style=flat-square)](https://github.com/dansbaker/gecko-intouch3-home-assistant/releases)
[![GitHub License](https://img.shields.io/github/license/dansbaker/gecko-intouch3-home-assistant.svg?style=flat-square)](LICENSE)
[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-2023.1%2B-blue.svg?style=flat-square)](https://www.home-assistant.io/)


## Quick Install

1. Copy the `custom_components/gecko_spa` folder into your Home Assistant config directory:

```bash
cp -r custom_components/gecko_spa /config/custom_components/
```

2. Restart Home Assistant

3. Add the integration through **Settings → Devices & Services → Add Integration** and search for "Gecko Spa Controller"

## Available Entities

After successful setup you should see entities such as:

- `climate.gecko_spa_temperature` - Temperature control
- `switch.gecko_spa_lights` - Lighting control
- `switch.gecko_spa_pump_1` - Pump 1 control
- `switch.gecko_spa_pump_2` - Pump 2 control (if available)
- `switch.gecko_spa_pump_3` - Pump 3 control (if available)


If authentication fails, the logs will report one of the following high-level reasons:
- invalid credentials
- network/connectivity issues
- rate-limiting by the authentication service

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This is an unofficial integration. Gecko, InTouch, and related trademarks are property of their respective owners.

## Support

- **Issues**: https://github.com/dansbaker/gecko-intouch3-home-assistant/issues
  - When reporting issues, please include the debug file generated by `gecko_debug_tool.py`
- **Discussions**: https://github.com/dansbaker/gecko-intouch3-home-assistant/discussions
