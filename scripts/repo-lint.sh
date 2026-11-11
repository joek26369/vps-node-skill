#!/usr/bin/env bash
# repo-lint.sh — 本仓库自检：脚本语法 + 敏感值泄露扫描
#
# 用法：
#   bash scripts/repo-lint.sh            # 本地或 CI 中运行
#   bash scripts/repo-lint.sh --verbose  # 打印每个被放行的匹配
#
# 退出码：0 = 干净；1 = 有问题；2 = 环境异常
#
# 设计要点：
#   - CI 里只能跑「通用规则」（IPv4 / 家目录 / 邮箱），不能把个人值写进仓库。
#   - 个人专属的敏感词放在 .github/sensitive-blocklist.local.txt（已 gitignore），
#     本地跑时自动加载，CI 里不存在该文件就自动跳过。
#   - 某行若确实需要保留（例如文档里的示例），在该行末尾加 `# lint-allow`
#     即可放行。

set -uo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd) || exit 2
cd "$REPO_ROOT" || exit 2

VERBOSE=0
[ "${1:-}" = "--verbose" ] && VERBOSE=1

FAIL=0
NOTE=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }
note() { if [ "$VERBOSE" = 1 ]; then printf '  \033[2m· %s\033[0m\n' "$*"; fi; }

# ---- 待检文件清单（只用一次）----
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  FILE_LIST=$(git ls-files)
else
  FILE_LIST=$(find . -type f ! -path './.git/*' ! -path './.workbuddy/*' | sed 's|^\./||')
fi

# 文本类文件才做内容扫描
TEXT_EXTS='sh|py|md|json|yml|yaml|txt|conf|service|command|toml'

echo "== 1/3 shell 语法 =="
n=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    *.sh)
      n=$((n + 1))
      if bash -n "$f" 2>/dev/null; then
        note "ok $f"
      else
        fail "语法错误：$f"
        bash -n "$f" 2>&1 | sed 's/^/      /'
      fi
      ;;
  esac
done <<< "$FILE_LIST"
if [ "$n" -eq 0 ]; then
  fail "未找到任何 .sh 脚本（路径异常？）"
else
  pass "$n 个 shell 脚本语法通过"
fi

echo "== 2/3 python 语法 =="
PY_FILES=""
while IFS= read -r f; do
  case "$f" in *.py) PY_FILES="$PY_FILES $f" ;; esac
done <<< "$FILE_LIST"
if [ -z "$PY_FILES" ]; then
  pass "无 python 文件，跳过"
else
  # ast.parse 不落 __pycache__，比 py_compile 干净
  if python3 - $PY_FILES <<'PY' 2>&1 | sed 's/^/      /'
import ast, sys
bad = 0
for f in sys.argv[1:]:
    try:
        with open(f, encoding="utf-8") as fh:
            ast.parse(fh.read(), f)
    except SyntaxError as e:
        print(f"语法错误：{f}:{e.lineno}: {e.msg}")
        bad = 1
sys.exit(bad)
PY
  then
    pass "$(echo $PY_FILES | wc -w | tr -d ' ') 个 python 文件语法通过"
  else
    fail "python 语法检查未通过"
  fi
fi

echo "== 3/3 敏感值扫描 =="

# 通用规则：命中的行进入二次判定，避免误报
scan_rule() {
  rule_name="$1"
  pattern="$2"
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    case "$f" in
      *.png|*.jpg|*.jpeg|*.gif|*.svg|*.ico|*.zip|*.gz|*.tar) continue ;;
    esac
    grep -nE "$pattern" "$f" 2>/dev/null | while IFS= read -r hit; do
      printf '%s\t%s\n' "$f" "$hit"
    done
  done <<< "$FILE_LIST"
}

# 判断一个 IPv4 是否属于「可以公开」的段
ip_is_public_sensitive() {
  ip="$1"
  o1=$(echo "$ip" | cut -d. -f1)
  o2=$(echo "$ip" | cut -d. -f2)
  case "$o1" in
    0|10|127|255) return 1 ;;
    169) [ "$o2" = 254 ] && return 1 ;;
    100) [ "$o2" -ge 64 ] 2>/dev/null && [ "$o2" -le 127 ] && return 1 ;;
    172) [ "$o2" -ge 16 ] 2>/dev/null && [ "$o2" -le 31 ] && return 1 ;;
    192)
      [ "$o2" = 168 ] && return 1
      [ "$o2" = 0 ] && return 1
      ;;
    198)
      [ "$o2" = 18 ] && return 1
      [ "$o2" = 19 ] && return 1
      [ "$o2" = 51 ] && return 1
      ;;
    203) [ "$o2" = 0 ] && return 1 ;;
  esac
  # 文档/示例地址、公共解析器（无隐私含义）
  case "$ip" in
    8.8.8.8|8.8.4.4|1.1.1.1|1.0.0.1|1.2.3.4|9.9.9.9|208.67.222.222) return 1 ;;
    114.114.114.114|223.5.5.5|223.6.6.6|119.29.29.29|180.76.76.76) return 1 ;;
  esac
  return 0
}

IP_HITS=$(scan_rule ipv4 '(^|[^0-9.])([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})([^0-9.]|$)')
IP_SAFE=0
if [ -n "$IP_HITS" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in *lint-allow*) IP_SAFE=$((IP_SAFE + 1)); note "allow: $line"; continue ;; esac
    # UA 字符串里的版本号（Chrome/131.0.0.0）不是 IP
    case "$line" in
      *Mozilla/5.0*|*AppleWebKit*|*Chrome/*) IP_SAFE=$((IP_SAFE + 1)); note "skip UA ($line)"; continue ;;
    esac
    f=${line%%$'\t'*}
    body=${line#*$'\t'}
    ip=$(printf '%s\n' "$body" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    if ip_is_public_sensitive "$ip"; then
      fail "公网 IPv4：$f:$body"
    else
      IP_SAFE=$((IP_SAFE + 1))
      note "skip $ip ($f)"
    fi
  done <<< "$IP_HITS"
  pass "IPv4 扫描完成（$IP_SAFE 处为示例/私有/UA 版本号，已放行）"
else
  pass "无 IPv4 字面量"
fi

# 家目录绝对路径
HOME_HITS=$(scan_rule home '(/Users/|/home/)[A-Za-z0-9._-]+')
if [ -n "$HOME_HITS" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in *lint-allow*) continue ;; esac
    fail "个人绝对路径：${line%%$'\t'*}:${line#*$'\t'}"
  done <<< "$HOME_HITS"
else
  pass "无个人绝对路径"
fi

# 邮箱（排除 github 的固定 noreply / 占位符）
MAIL_HITS=$(scan_rule email '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
if [ -n "$MAIL_HITS" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in
      *lint-allow*) continue ;;
      *users.noreply.github.com*) continue ;;
      *example.com*|*example.org*|*example.net*) continue ;;
      *git@github.com*|*noreply@*) continue ;;
    esac
    fail "邮箱：${line%%$'\t'*}:${line#*$'\t'}"
  done <<< "$MAIL_HITS"
else
  pass "无邮箱"
fi

# 本地私有黑名单（不提交）
BL=".github/sensitive-blocklist.local.txt"
if [ -f "$BL" ]; then
  c=0
  while IFS= read -r term; do
    [ -z "$term" ] && continue
    case "$term" in \#*) continue ;; esac
    c=$((c + 1))
    hits=$(grep -rnF -- "$term" . --exclude-dir=.git --exclude-dir=.workbuddy 2>/dev/null \
           | grep -v 'sensitive-blocklist.local' || true)
    if [ -n "$hits" ]; then
      while IFS= read -r h; do
        [ -z "$h" ] && continue
        case "$h" in *lint-allow*) continue ;; esac
        fail "私有黑名单命中「${term}」：${h}"
      done <<< "$hits"
    fi
  done < "$BL"
  pass "私有黑名单 $c 条已检查"
else
  note "无 ${BL}，跳过私有黑名单"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32m全部通过\033[0m\n'
  exit 0
fi
printf '\033[31m%d 项未通过\033[0m\n' "$FAIL"
exit 1
