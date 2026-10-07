#!/bin/sh
# Builds the GUI as a macOS app: target/release/bundle/ndiscover.app
#
# Put a square PNG (ideally 1024x1024) at assets/icon.png to give the app an icon.
set -eu

cd "$(dirname "$0")/.."

IDENTIFIER="com.ndiscover.ndiscover"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
APP="target/release/bundle/ndiscover.app"

cargo build --release --features gui --bin ndiscover

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release/ndiscover "$APP/Contents/MacOS/ndiscover"

ICON_KEY=""
if [ -f assets/icon.png ]; then
    WIDTH=$(sips -g pixelWidth assets/icon.png | awk '/pixelWidth/ { print $2 }')
    if [ "$WIDTH" -lt 1024 ]; then
        echo "warning: assets/icon.png is ${WIDTH}px wide, it looks blurry in the Dock below 1024px" >&2
    fi
    ICONSET="target/release/bundle/ndiscover.iconset"
    rm -rf "$ICONSET"
    mkdir -p "$ICONSET"
    for size in 16 32 128 256 512; do
        sips -z "$size" "$size" assets/icon.png --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
        double=$((size * 2))
        sips -z "$double" "$double" assets/icon.png --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
    done
    iconutil --convert icns "$ICONSET" --output "$APP/Contents/Resources/ndiscover.icns"
    rm -rf "$ICONSET"
    ICON_KEY="<key>CFBundleIconFile</key><string>ndiscover</string>"
fi

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>ndiscover</string>
    <key>CFBundleDisplayName</key><string>ndiscover</string>
    <key>CFBundleIdentifier</key><string>$IDENTIFIER</string>
    <key>CFBundleExecutable</key><string>ndiscover</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>ndiscover searches the local network for NETIO devices and controls them.</string>
    $ICON_KEY
</dict>
</plist>
EOF

# Ad-hoc signature, enough to run the app on this Mac
codesign --force --sign - "$APP"

echo "Built $APP"
