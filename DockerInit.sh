#!/bin/sh
set -e
XRAY_VER="v26.6.27"
SINGBOX_VER="1.14.2"
case $1 in
    arm64 | armv8 | aarch64)
        ARCH="arm64-v8a"
        FNAME="arm64"
        TUIC="aarch64-unknown-linux-musl"
        ;;
    *)
        ARCH="64"
        FNAME="amd64"
        TUIC="x86_64-unknown-linux-musl"
        ;;
esac
MTG_MULTI_VER=$(curl -sfL "https://api.github.com/repos/mhsanaei/mtg-multi/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
if [ -z "$MTG_MULTI_VER" ]; then
    echo "DockerInit: could not resolve the latest mtg-multi release tag" >&2
    exit 1
fi
mkdir -p build/bin
cd build/bin
curl -sfLRO "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-${ARCH}.zip"
unzip "Xray-linux-${ARCH}.zip"
rm -f "Xray-linux-${ARCH}.zip" geoip.dat geosite.dat
mv xray "xray-linux-${FNAME}"
# sing-box sidecar (protocols xray lacks); the tarball nests the binary in a folder.
SB_PKG="sing-box-${SINGBOX_VER}-linux-${FNAME}"
curl -sfLRO "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/${SB_PKG}.tar.gz"
tar -xzf "${SB_PKG}.tar.gz"
mv "${SB_PKG}/sing-box" "sing-box-linux-${FNAME}"
rm -rf "${SB_PKG}" "${SB_PKG}.tar.gz"
chmod +x "sing-box-linux-${FNAME}"
# mtg-multi (MTProto sidecar) ships prebuilt release binaries for every target
# we package, so download and unpack the matching one instead of compiling.
MTG_PKG="mtg-multi-${MTG_MULTI_VER#v}-linux-${FNAME}"
curl -sfLRO "https://github.com/mhsanaei/mtg-multi/releases/download/${MTG_MULTI_VER}/${MTG_PKG}.tar.gz"
tar -xzf "${MTG_PKG}.tar.gz"
mv "${MTG_PKG}/mtg-multi" "mtg-linux-${FNAME}"
rm -rf "${MTG_PKG}" "${MTG_PKG}.tar.gz"
chmod +x "mtg-linux-${FNAME}"
curl -sfLRo "tuic-server" "https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-${TUIC}"
if [ ! -s "tuic-server" ]; then
    echo "DockerInit: tuic-server download was empty" >&2
    exit 1
fi
chmod +x "tuic-server"
curl -sfLRO https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
curl -sfLRO https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
curl -sfLRo geoip_IR.dat https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat
curl -sfLRo geosite_IR.dat https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat
curl -sfLRo geoip_RU.dat https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat
curl -sfLRo geosite_RU.dat https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat
cd ..
# acme.sh is bundled so the in-container SSL menu never needs get.acme.sh.
mkdir -p acme-bundle
curl -sfL "https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz" | tar -xz --strip-components=1 -C acme-bundle
cd ..
