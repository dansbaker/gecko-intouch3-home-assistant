#!/bin/bash

# Version bump script for Gecko InTouch3 Home Assistant Integration
# Usage: ./bump_version.sh [major|minor|patch] [version]
# Examples:
#   ./bump_version.sh patch        # 0.0.1 -> 0.0.2
#   ./bump_version.sh minor        # 0.0.1 -> 0.1.0  
#   ./bump_version.sh major        # 0.0.1 -> 1.0.0
#   ./bump_version.sh 0.2.3        # Set to specific version

set -e

CURRENT_VERSION=$(grep '"version"' custom_components/gecko_spa/manifest.json | cut -d'"' -f4)
echo "Current version: $CURRENT_VERSION"

if [ $# -eq 0 ]; then
    echo "Usage: $0 [major|minor|patch|version]"
    echo "Current version: $CURRENT_VERSION"
    exit 1
fi

# Parse current version
IFS='.' read -r major minor patch <<< "$CURRENT_VERSION"

case "$1" in
    "major")
        NEW_VERSION="$((major + 1)).0.0"
        ;;
    "minor") 
        NEW_VERSION="$major.$((minor + 1)).0"
        ;;
    "patch")
        NEW_VERSION="$major.$minor.$((patch + 1))"
        ;;
    [0-9]*)
        NEW_VERSION="$1"
        ;;
    *)
        echo "Invalid argument. Use: major, minor, patch, or a version number"
        exit 1
        ;;
esac

echo "Bumping version from $CURRENT_VERSION to $NEW_VERSION"

# Update manifest.json
sed -i.bak "s/\"version\": \"$CURRENT_VERSION\"/\"version\": \"$NEW_VERSION\"/" custom_components/gecko_spa/manifest.json

# Update version.py
cat > custom_components/gecko_spa/version.py << EOF
"""Version information for Gecko Spa integration."""

__version__ = "$NEW_VERSION"
__version_info__ = ($(echo $NEW_VERSION | tr '.' ','))

VERSION = __version__
EOF

# Update CHANGELOG.md with new version header
if ! grep -q "### v$NEW_VERSION" CHANGELOG.md; then
    # Add new version section at the top
    sed -i.bak "s/^## Release History/## Release History\n\n### v$NEW_VERSION - $(date +%Y-%m-%d)\n\n**Changes:**\n- \n\n**Fixes:**\n- \n/" CHANGELOG.md
fi

echo "✅ Updated version to $NEW_VERSION"
echo ""
echo "Next steps:"
echo "1. Update CHANGELOG.md with release notes"
echo "2. Commit changes: git add . && git commit -m 'Bump version to $NEW_VERSION'"
echo "3. Create tag: git tag v$NEW_VERSION"
echo "4. Push: git push && git push --tags"

# Clean up backup files
rm -f custom_components/gecko_spa/manifest.json.bak CHANGELOG.md.bak