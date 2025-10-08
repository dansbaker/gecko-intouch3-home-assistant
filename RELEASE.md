# Release Instructions

## Quick Release Process

### 1. Bump Version
```bash
# For patch release (0.0.1 -> 0.0.2)
./bump_version.sh patch

# For minor release (0.0.1 -> 0.1.0)  
./bump_version.sh minor

# For major release (0.0.1 -> 1.0.0)
./bump_version.sh major

# For specific version
./bump_version.sh 0.2.5
```

### 2. Update Changelog
Edit `CHANGELOG.md` to add release notes for the new version:
```markdown
### v0.0.2 - 2025-10-05

**Features:**
- Added new pump control feature
- Improved error handling

**Fixes:**  
- Fixed connection timeout issue
- Resolved temperature sensor bug
```

### 3. Commit and Tag
```bash
# Commit changes
git add .
git commit -m "Bump version to v0.0.2"

# Create and push tag
git tag v0.0.2
git push origin master
git push origin v0.0.2
```

### 4. GitHub Release
The GitHub Actions workflow will automatically:
- ✅ Create a GitHub release
- ✅ Generate release notes from CHANGELOG.md
- ✅ Package the integration as a ZIP file
- ✅ Attach the ZIP to the release

## Manual GitHub Release (Alternative)

1. Go to [GitHub Releases](https://github.com/dansbaker/gecko-intouch3-home-assistant/releases)
2. Click **"Create a new release"**
3. Choose the tag (e.g., `v0.0.2`)
4. Title: `Gecko InTouch3 HA Integration v0.0.2`
5. Copy release notes from CHANGELOG.md
6. Attach `gecko_spa_0.0.2.zip` file
7. Publish release

## Version Locations

The version number is automatically maintained in:
- ✅ `custom_components/gecko_spa/manifest.json`
- ✅ `custom_components/gecko_spa/version.py`
- ✅ `setup.py`
- ✅ `CHANGELOG.md`

## Installation for Users

Users can download releases from:
```
https://github.com/dansbaker/gecko-intouch3-home-assistant/releases/latest
```

Each release includes:
- Complete integration package
- Installation instructions  
- Changelog
- Version compatibility info