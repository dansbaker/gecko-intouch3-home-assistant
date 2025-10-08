# Gecko InTouch3 Home Assistant Integration

## Release History

### v0.0.1 - Initial Release (2025-10-05)

**Features:**
- ✅ **Real-time Control**: Turn pumps and lights on/off instantly
- ✅ **Live Monitoring**: Temperature, heating status, flow status  
- ✅ **Multiple Entities**: Individual controls for each pump (up to 3) and lights
- ✅ **Event-Driven Architecture**: Uses AWS IoT MQTT for immediate updates (no polling delays)
- ✅ **Optimistic UI Updates**: Immediate visual feedback when toggling controls
- ✅ **OAuth2 + AWS IoT Integration**: Complete authentication pipeline
- ✅ **Automatic Token Refresh**: Handles token expiration seamlessly
- ✅ **Connection Recovery**: Automatic reconnection on network issues
- ✅ **HACS Compatible**: Proper configuration for HACS installation

**Technical Details:**
- OAuth2 authentication with Gecko's Auth0 service
- AWS IoT MQTT shadow state for real-time device communication
- Home Assistant config flow for easy setup
- Support for multiple pump configurations
- Temperature control with climate entity
- Individual switch entities for pumps and lighting
- Optimistic state updates with 10-second expiry
- Event-driven callbacks instead of polling

**Setup Requirements:**
- Charles Proxy or similar tool to capture OAuth tokens
- Home Assistant 2023.1 or later
- Internet connectivity for cloud services

**Known Limitations:**
- Requires manual OAuth token capture during initial setup
- Single spa support per integration instance
- iOS/Android app required for token capture

---

## Development Notes

This release establishes the foundation for Gecko InTouch3 spa control in Home Assistant. The integration provides both monitoring and control capabilities through a cloud-connected MQTT pipeline.

### Architecture
- **Authentication Layer**: OAuth2 → AWS IoT credentials
- **Communication Layer**: AWS IoT MQTT with shadow state
- **Integration Layer**: Home Assistant coordinator + entities
- **UI Layer**: Climate and switch entities with optimistic updates

- Event-driven callbacks instead of polling### v0.0.3 - 2025-10-05



**Setup Requirements:****HACS Compatibility:**

- Charles Proxy or similar tool to capture OAuth tokens- ✅ **Added HACS Support**: Added `hacs.json` configuration for proper HACS integration

- Home Assistant 2023.1 or later- ✅ **Fixed Download Issues**: Resolved "404 when trying to download" errors in HACS

- Internet connectivity for cloud services- ✅ **Improved Release Format**: Updated GitHub Actions to create HACS-compatible ZIP files

- ✅ **Modern Workflow**: Migrated to `softprops/action-gh-release` for better reliability

**Known Limitations:**

- Requires manual OAuth token capture during initial setup**Technical Improvements:**

- Single spa support per integration instance- Fixed ZIP file structure for HACS (`custom_components/` in root)

- iOS/Android app required for token capture- Added proper HACS metadata with `zip_release: true`

- Updated release workflow to use semantic versioning properly

---- Enhanced GitHub Actions for automated HACS-compatible releases



## Development Notes**For HACS Users:**

- Repository can now be added as custom integration in HACS

This release establishes the foundation for Gecko InTouch3 spa control in Home Assistant. The integration provides both monitoring and control capabilities through a cloud-connected MQTT pipeline.- Downloads will use proper version numbers instead of commit hashes

- ZIP files are properly structured for automatic installation

### Architecture

- **Authentication Layer**: OAuth2 → AWS IoT credentials

- **Communication Layer**: AWS IoT MQTT with shadow state### v0.0.2 - 2025-10-05

- **Integration Layer**: Home Assistant coordinator + entities

- **UI Layer**: Climate and switch entities with optimistic updates**Fixes:**
- ✅ **Critical Fix**: Added missing `_set_optimistic_state` method to `GeckoPumpSwitch` class
- ✅ **Pump Controls**: Resolved AttributeError that prevented pump switches from turning on/off
- ✅ **UI Responsiveness**: Pump switches now provide immediate UI feedback like light switches
- ✅ **Optimistic Updates**: 10-second optimistic state window for all switch entities

**Technical Details:**
- Fixed `'GeckoPumpSwitch' object has no attribute '_set_optimistic_state'` error
- Added optimistic state management with datetime-based expiry
- Consistent behavior between light and pump switch entities


### v0.0.1 - Initial Release (2025-10-05)

**Features:**
- ✅ **Real-time Control**: Turn pumps and lights on/off instantly
- ✅ **Live Monitoring**: Temperature, heating status, flow status  
- ✅ **Multiple Entities**: Individual controls for each pump (up to 3) and lights
- ✅ **Event-Driven Architecture**: Uses AWS IoT MQTT for immediate updates (no polling delays)
- ✅ **Optimistic UI Updates**: Immediate visual feedback when toggling controls
- ✅ **OAuth2 + AWS IoT Integration**: Complete authentication pipeline
- ✅ **Automatic Token Refresh**: Handles token expiration seamlessly
- ✅ **Connection Recovery**: Automatic reconnection on network issues

**Technical Details:**
- OAuth2 authentication with Gecko's Auth0 service
- AWS IoT MQTT shadow state for real-time device communication
- Home Assistant config flow for easy setup
- Support for multiple pump configurations
- Temperature control with climate entity
- Individual switch entities for pumps and lighting

**Setup Requirements:**
- Charles Proxy or similar tool to capture OAuth tokens
- Home Assistant 2023.1 or later
- Internet connectivity for cloud services

**Known Limitations:**
- Requires manual OAuth token capture during initial setup
- Single spa support per integration instance
- iOS/Android app required for token capture

---

## Development Notes

This release establishes the foundation for Gecko InTouch3 spa control in Home Assistant. The integration provides both monitoring and control capabilities through a cloud-connected MQTT pipeline.

### Architecture
- **Authentication Layer**: OAuth2 → AWS IoT credentials
- **Communication Layer**: AWS IoT MQTT with shadow state
- **Integration Layer**: Home Assistant coordinator + entities
- **UI Layer**: Climate and switch entities with optimistic updates