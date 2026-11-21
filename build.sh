#!/usr/bin/env bash
# ============================================================================
# BurpCrypto · Body 透明加解密 —— 一键编译打包
#
# 用法：
#   ./build.sh              # 编译 + 打包 jar
#   ./build.sh --tests      # 编译 + 跑单元测试 + 打包
#   ./build.sh --clean      # 先清理
#
# 说明：
#   · 编译只依赖两样东西：完整 JDK 17+ 与 Burp 自己的 burpsuite_pro.jar
#     （Montoya API 就在里面，不需要联网下载任何依赖）。
#   · 目标字节码 release 17，Burp 2023.12+ 均可加载。
#   · 可用环境变量覆盖：JAVA_HOME、BURP_JAR
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

VERSION="1.7.2"
OUT_JAR="build/BurpCryptCat-${VERSION}.jar"

find_jdk() {
  jdk_ok() {  # 版本 >= 17 才算可用
    local d="$1"
    [ -x "$d/bin/javac" ] || return 1
    local v
    v=$("$d/bin/javac" -version 2>&1 | sed -n 's/^javac \([0-9]*\).*/\1/p')
    [ -n "$v" ] && [ "$v" -ge 17 ]
  }
  if [ -n "${JAVA_HOME:-}" ] && jdk_ok "$JAVA_HOME"; then
    echo "$JAVA_HOME"; return
  fi
  for d in "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home \
           /Library/Java/JavaVirtualMachines/*/Contents/Home; do
    if jdk_ok "$d"; then echo "$d"; return; fi
  done
  if h=$(/usr/libexec/java_home -v 17 2>/dev/null) && [ -x "$h/bin/javac" ]; then
    echo "$h"; return
  fi
  if command -v javac >/dev/null 2>&1; then
    v=$(javac -version 2>&1 | sed -n 's/^javac \([0-9]*\).*/\1/p')
    if [ -n "$v" ] && [ "$v" -ge 17 ]; then dirname "$(dirname "$(command -v javac)")"; return; fi
  fi
  return 1
}

find_burp() {
  if [ -n "${BURP_JAR:-}" ] && [ -f "$BURP_JAR" ]; then echo "$BURP_JAR"; return; fi
  for f in "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar" \
           "/Applications/Burp Suite Community Edition.app/Contents/Resources/app/burpsuite.jar" \
           "$HOME/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar"; do
    [ -f "$f" ] && { echo "$f"; return; }
  done
  return 1
}

JDK=$(find_jdk || true)
if [ -z "$JDK" ]; then
  cat <<'EOF'
[!] 找不到 JDK 17+。
    macOS 建议：brew install openjdk@21  或  从 https://adoptium.net 下载后解包到
    ~/Library/Java/JavaVirtualMachines/
    也可以用 Java_home 指定：JAVA_HOME=/path/to/jdk ./build.sh
EOF
  exit 1
fi

RHINO="lib/rhino-1.7.15.jar"
if [ ! -f "$RHINO" ]; then
  echo "[i] 下载 JS 脚本引擎 Rhino（脚本方式需要）…"
  mkdir -p lib
  curl -sS -m 120 -o "$RHINO" \
    "https://repo.maven.apache.org/maven2/org/mozilla/rhino/1.7.15/rhino-1.7.15.jar" || {
      echo "[!] 下载失败。脚本方式需要 Rhino，可手动放到 $RHINO"; exit 1; }
fi

BURP=$(find_burp || true)
if [ -z "$BURP" ]; then
  cat <<'EOF'
[!] 找不到 Burp 的 jar（Montoya API 在里面）。
    请用 BURP_JAR=/path/to/burpsuite_pro.jar ./build.sh 指定。
EOF
  exit 1
fi

if [ "${1:-}" = "--clean" ]; then
  rm -rf build
  echo "[i] 已清理 build/"
  exit 0
fi

echo "[i] JDK  : $JDK"
"$JDK/bin/javac" -version
echo "[i] Burp : $BURP"
echo

rm -rf build/classes build/test-classes
mkdir -p build/classes

echo "[1/3] 编译扩展"
"$JDK/bin/javac" --release 17 -Xlint:all,-serial,-removal -encoding UTF-8 \
  -cp "$BURP:$RHINO" -d build/classes $(find src/main/java -name '*.java')

if [ "${1:-}" = "--tests" ]; then
  echo "[2/3] 编译并运行单元测试"
  mkdir -p build/test-classes
  "$JDK/bin/javac" --release 17 -nowarn -encoding UTF-8 \
    -cp "build/classes:$RHINO" -d build/test-classes $(find tests/java -name '*.java')
  "$JDK/bin/java" -cp "build/classes:build/test-classes:$RHINO" burp.tests.BurpCryptoTests
else
  echo "[2/3] 跳过单元测试（加 --tests 可运行）"
fi

echo "[3/3] 打包 jar（把 Rhino 一起打进去，用户只需要一个 jar）"
"$JDK/bin/jar" --extract --file "$RHINO" --dir build/classes 2>/dev/null || {
  cd build/classes && "$JDK/bin/jar" xf "../../$RHINO" && cd ../..
}
rm -rf build/classes/META-INF
mkdir -p build
cat > build/MANIFEST.MF <<EOF
Implementation-Title: BurpCryptCat
Implementation-Version: ${VERSION}
Implementation-Vendor: based on whwlsfb/BurpCrypto
EOF
"$JDK/bin/jar" --create --file "$OUT_JAR" --manifest build/MANIFEST.MF -C build/classes .
ls -lh "$OUT_JAR"

cat <<EOF

✅ 完成：$(pwd)/${OUT_JAR}

在 Burp 里加载：
  Extensions → Installed → Add
    Extension type : Java
    Extension file : ${OUT_JAR}

加载后到 BurpCrypto 页签：① 配置方案填 Key/IV → ② 生效规则按 Host/URL 启用。
EOF
