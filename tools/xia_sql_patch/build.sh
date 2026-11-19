#!/usr/bin/env bash
# ============================================================================
# 给 xia SQL 打「BurpCrypto 桥接」补丁并打包
#
# 用法：
#   ./build.sh                              # 默认用 BurpExtender.3.3.java.patched（基于 3.3 字节码反编译后打补丁）
#   ./build.sh ../BurpExtender.java         # 也可传入上游源码（若作者日后补上 3.3 源码）
#
# 依赖：JDK 17+、本机 Burp 的 burpsuite_pro.jar（里面有旧版扩展 API），或 BURP_JAR 指定
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

SRC="${1:-BurpExtender.3.3.java.patched}"
OUT="xia_sql_3.3_cryptcat.jar"

find_jdk() {
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then
    v=$("$JAVA_HOME/bin/javac" -version 2>&1 | sed -n 's/^javac \([0-9]*\).*/\1/p')
    [ -n "$v" ] && [ "$v" -ge 17 ] && { echo "$JAVA_HOME"; return; }
  fi
  for d in "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home \
           /Library/Java/JavaVirtualMachines/*/Contents/Home; do
    [ -x "$d/bin/javac" ] || continue
    v=$("$d/bin/javac" -version 2>&1 | sed -n 's/^javac \([0-9]*\).*/\1/p')
    [ -n "$v" ] && [ "$v" -ge 17 ] && { echo "$d"; return; }
  done
  return 1
}

BURP_JAR="${BURP_JAR:-/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar}"
JDK=$(find_jdk || true)
[ -n "$JDK" ] || { echo "[!] 找不到 JDK 17+"; exit 1; }
[ -f "$BURP_JAR" ] || { echo "[!] 找不到 Burp jar：$BURP_JAR（用 BURP_JAR=... 指定）"; exit 1; }

echo "[i] JDK : $JDK"
echo "[i] 源码: $SRC"
rm -rf build && mkdir -p build/src build/classes
cp "$SRC" build/src/BurpExtender.java
cp xiabridge/CatBridge.java build/src/

"$JDK/bin/javac" --release 17 -nowarn -encoding UTF-8 \
  -cp "$BURP_JAR" -d build/classes build/src/*.java

cat > build/MANIFEST.MF <<'M'
Implementation-Title: xia SQL 3.3 + BurpCryptoBridge
Implementation-Version: 3.3-burpcrypto-1.0
M
"$JDK/bin/jar" --create --file "$OUT" --manifest build/MANIFEST.MF -C build/classes .
echo
echo "✅ 生成：$(pwd)/$OUT"
echo "   Burp 里先把旧的 xia SQL 移除，再 Add 这个 jar（Extension type: Java）"
