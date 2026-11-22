#!/usr/bin/env bash
# cargo-dist 0.34.0 skips Unix checksum verification when sha256sum is absent
# (including stock macOS) and does not verify the separate updater download.
# Embed updater SHA-256 digests and enforce fail-closed verification for both
# the archive and updater before testing or publishing.
set -euo pipefail

usage() {
    echo "usage: $0 [--distrib] <distrib-dir>" >&2
    exit 2
}

distrib=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --distrib)
            [ "$#" -ge 2 ] || usage
            distrib="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            usage
            ;;
        *)
            [ -z "$distrib" ] || usage
            distrib="$1"
            shift
            ;;
    esac
done

[ -n "$distrib" ] || usage
[ -d "$distrib" ] || { echo "error: distrib directory does not exist: $distrib" >&2; exit 1; }

installer_path="${distrib%/}/kickoutchi-installer.sh"
if [ -L "$installer_path" ] || [ ! -f "$installer_path" ]; then
    echo "error: expected regular installer file: $installer_path" >&2
    exit 1
fi

if grep -q 'verify_release_sha256()' "$installer_path"; then
    echo "error: the Unix installer already has release checksum checks" >&2
    exit 1
fi

compute_sha256() {
    local file="$1"
    local digest=""
    if [ -L "$file" ] || [ ! -f "$file" ]; then
        echo "error: expected regular release artifact: $file" >&2
        exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        digest="$(sha256sum < "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        digest="$(shasum -a 256 < "$file" | awk '{print $1}')"
    elif command -v openssl >/dev/null 2>&1; then
        digest="$(openssl dgst -sha256 < "$file" | awk '{print $NF}')"
    else
        echo "error: no SHA-256 tool (sha256sum, shasum, or openssl) available to protect installer" >&2
        exit 1
    fi
    digest="$(printf '%s' "$digest" | tr 'A-F' 'a-f')"
    if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
        echo "error: invalid SHA-256 digest computed for $file: $digest" >&2
        exit 1
    fi
    printf '%s' "$digest"
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
staged="${tmp_dir}/kickoutchi-installer.sh"

# Pass 1: validate every target arm's archive hash, embed updater hashes, and
# declare the local _updater_checksum_value variable.
in_case=0
current_artifact=""
saw_checksum_style=0
saw_checksum_value=0
saw_updater=0
arms_patched=0
local_decl_count=0

while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = "    local _checksum_value" ]; then
        local_decl_count=$((local_decl_count + 1))
        printf '%s\n' "$line"
        printf '    local _updater_checksum_value=""\n'
        continue
    fi

    if [ "$line" = '    case "$_artifact_name" in ' ] || [ "$line" = '    case "$_artifact_name" in' ]; then
        in_case=1
        printf '%s\n' "$line"
        continue
    fi

    if [ "$in_case" = 1 ]; then
        if [ "$line" = "    esac" ]; then
            in_case=0
            current_artifact=""
            printf '%s\n' "$line"
            continue
        fi

        if [[ "$line" =~ ^[[:space:]]+\"([^\"]+)\"\)$ ]]; then
            current_artifact="${BASH_REMATCH[1]}"
            saw_checksum_style=0
            saw_checksum_value=0
            saw_updater=0
            printf '%s\n' "$line"
            continue
        fi

        if [ -n "$current_artifact" ]; then
            if [[ "$line" =~ ^[[:space:]]+_checksum_style=\"([^\"]*)\"$ ]]; then
                if [ "${BASH_REMATCH[1]}" != "sha256" ]; then
                    echo "error: expected sha256 checksum style for $current_artifact, got '${BASH_REMATCH[1]}'" >&2
                    exit 1
                fi
                saw_checksum_style=1
                printf '%s\n' "$line"
                continue
            fi

            if [[ "$line" =~ ^[[:space:]]+_checksum_value=\"([^\"]*)\"$ ]]; then
                embedded="$(printf '%s' "${BASH_REMATCH[1]}" | tr 'A-F' 'a-f')"
                actual="$(compute_sha256 "${distrib%/}/${current_artifact}")"
                if [ "$embedded" != "$actual" ]; then
                    echo "error: archive checksum mismatch for $current_artifact (template=$embedded, distrib=$actual)" >&2
                    exit 1
                fi
                saw_checksum_value=1
                printf '%s\n' "$line"
                continue
            fi

            if [[ "$line" =~ ^([[:space:]]+)_updater_name=\"([^\"]+)\"$ ]]; then
                indent="${BASH_REMATCH[1]}"
                updater_name="${BASH_REMATCH[2]}"
                updater_hash="$(compute_sha256 "${distrib%/}/${updater_name}")"
                saw_updater=1
                printf '%s\n' "$line"
                printf '%s_updater_checksum_value="%s"\n' "$indent" "$updater_hash"
                continue
            fi

            re_arm_end='^[[:space:]]+;;$'
            if [[ "$line" =~ $re_arm_end ]]; then
                if [ "$saw_checksum_style" != 1 ] || [ "$saw_checksum_value" != 1 ] || [ "$saw_updater" != 1 ]; then
                    echo "error: incomplete target arm for $current_artifact (style=$saw_checksum_style, value=$saw_checksum_value, updater=$saw_updater)" >&2
                    exit 1
                fi
                arms_patched=$((arms_patched + 1))
                current_artifact=""
            fi
        fi
    fi

    printf '%s\n' "$line"
done < "$installer_path" > "${tmp_dir}/pass1.sh"

if [ "$local_decl_count" != 1 ]; then
    echo "error: unexpected cargo-dist Unix template: expected 1 'local _checksum_value', found $local_decl_count" >&2
    exit 1
fi
if [ "$arms_patched" -lt 1 ]; then
    echo "error: unexpected cargo-dist Unix template: no target arms patched" >&2
    exit 1
fi

# Pass 2: make archive verification mandatory, add updater verification before
# unpacking/installing, and replace verify_checksum with a fail-closed verifier.
awk '
BEGIN {
    archive_patched = 0
    updater_patched = 0
    verify_patched = 0
    skip_verify = 0
    n = 0
}
{
    lines[++n] = $0
}
END {
    i = 1
    while (i <= n) {
        if (i + 4 <= n &&
            lines[i] == "        if [ -n \"${_checksum_style:-}\" ]; then" &&
            lines[i+1] == "            verify_checksum \"$_file\" \"$_checksum_style\" \"$_checksum_value\"" &&
            lines[i+2] == "        else" &&
            lines[i+3] == "            say \"no checksums to verify\" 1>&2" &&
            lines[i+4] == "        fi") {
            archive_patched++
            print "        if [ \"${_checksum_style:-}\" != \"sha256\" ] || [ -z \"${_checksum_value:-}\" ]; then"
            print "            err \"missing embedded SHA-256 checksum for $_artifact_name\""
            print "        fi"
            print "        verify_checksum \"$_file\" \"$_checksum_style\" \"$_checksum_value\" \"$_artifact_name\""
            i += 5
            continue
        }

        if (i + 6 <= n &&
            lines[i] == "            if ! downloader \"$_updater_url\" \"$_updater_file\"; then" &&
            lines[i+1] == "                say \"failed to download $_updater_url\"" &&
            lines[i+2] == "                continue" &&
            lines[i+3] == "            fi" &&
            lines[i+4] == "" &&
            lines[i+5] == "            # Add the updater to the list of binaries to install" &&
            lines[i+6] == "            _bins=\"$_bins $APP_NAME-update\"") {
            updater_patched++
            print lines[i]
            print lines[i+1]
            print lines[i+2]
            print lines[i+3]
            print ""
            print "            if [ -z \"${_updater_checksum_value:-}\" ]; then"
            print "                err \"missing embedded SHA-256 checksum for $_updater_name\""
            print "            fi"
            print "            verify_checksum \"$_updater_file\" \"sha256\" \"$_updater_checksum_value\" \"$_updater_name\""
            print ""
            print lines[i+5]
            print lines[i+6]
            i += 7
            continue
        }

        if (lines[i] == "verify_checksum() {") {
            verify_patched++
            found_end = 0
            j = i + 1
            while (j <= n) {
                if (lines[j] == "}") {
                    found_end = j
                    break
                }
                j++
            }
            if (!found_end) {
                print "error: unterminated verify_checksum() in cargo-dist Unix template" > "/dev/stderr"
                exit 1
            }
            print "verify_release_sha256() {"
            print "    local _file=\"$1\""
            print "    local _artifact=\"$2\""
            print "    local _digest"
            print ""
            print "    if check_cmd sha256sum; then"
            print "        _digest=\"$(sha256sum < \"$_file\" | awk \x27{print $1}\x27)\" || err \"failed to compute SHA-256 for $_artifact using sha256sum\""
            print "    elif check_cmd shasum; then"
            print "        _digest=\"$(shasum -a 256 < \"$_file\" | awk \x27{print $1}\x27)\" || err \"failed to compute SHA-256 for $_artifact using shasum\""
            print "    elif check_cmd openssl; then"
            print "        _digest=\"$(openssl dgst -sha256 < \"$_file\" | awk \x27{print $NF}\x27)\" || err \"failed to compute SHA-256 for $_artifact using openssl\""
            print "    else"
            print "        err \"cannot verify SHA-256 checksum for $_artifact: install sha256sum, shasum, or openssl\""
            print "    fi"
            print ""
            print "    RETVAL=\"$(printf \x27%s\x27 \"$_digest\" | tr \x27A-F\x27 \x27a-f\x27)\""
            print "}"
            print ""
            print "verify_checksum() {"
            print "    local _file=\"$1\""
            print "    local _checksum_style=\"$2\""
            print "    local _checksum_value=\"$3\""
            print "    local _artifact=\"${4:-$_file}\""
            print "    local _expected_checksum"
            print "    local _calculated_checksum"
            print ""
            print "    if [ \"$_checksum_style\" != \"sha256\" ]; then"
            print "        err \"unsupported checksum style for $_artifact: $_checksum_style\""
            print "    fi"
            print "    _expected_checksum=\"$(printf \x27%s\x27 \"$_checksum_value\" | tr \x27A-F\x27 \x27a-f\x27)\""
            print "    case \"$_expected_checksum\" in"
            print "        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])"
            print "            ;;"
            print "        *)"
            print "            err \"invalid embedded SHA-256 checksum for $_artifact\""
            print "            ;;"
            print "    esac"
            print ""
            print "    verify_release_sha256 \"$_file\" \"$_artifact\""
            print "    _calculated_checksum=\"$RETVAL\""
            print ""
            print "    if [ \"$_calculated_checksum\" != \"$_expected_checksum\" ]; then"
            print "        err \"SHA-256 mismatch for $_artifact (expected $_expected_checksum, got $_calculated_checksum)\""
            print "    fi"
            print "}"
            i = found_end + 1
            continue
        }

        print lines[i]
        i++
    }

    if (archive_patched != 1 || updater_patched != 1 || verify_patched != 1) {
        printf "error: unexpected cargo-dist Unix template (archive=%d, updater=%d, verify=%d)\n", archive_patched, updater_patched, verify_patched > "/dev/stderr"
        exit 1
    }
}
' "${tmp_dir}/pass1.sh" > "$staged"

sh -n "$staged"
chmod --reference="$installer_path" "$staged" 2>/dev/null || chmod 0755 "$staged"
mv "$staged" "$installer_path"
