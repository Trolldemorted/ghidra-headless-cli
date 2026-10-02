#!/usr/bin/env bash
#
# Generate .classpath (and .project) so the jdtls-lsp Claude Code plugin can
# resolve symbols across files.
#
# Why this exists:
#   ghidra-rpc-server has no build system. `make lint` runs Checkstyle over the
#   sources and the Java is compiled at runtime by Ghidra's script host. Eclipse
#   JDT -- which jdtls is built on -- needs a .classpath to build a project
#   model. Without one it treats every file as standalone, silently degrades to
#   syntax-only diagnostics, and go-to-definition fails even for symbols that
#   are a directory away.
#
# Why generated rather than committed:
#   Eclipse does not support wildcard classpath entries (eclipse bug 577690 --
#   still unimplemented), so every jar has to be listed by path. The result is
#   large and hardcodes whichever Ghidra is on disk, so it must be regenerated
#   whenever the Ghidra version changes. It is gitignored for that reason.
#
# Usage:
#   ./tools/gen-classpath.sh              # auto-detect Ghidra
#   GHIDRA_HOME=/opt/ghidra_12.1.2_PUBLIC ./tools/gen-classpath.sh
#
# After regenerating, reload the LSP in Claude Code:
#   /reload-plugins --force
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

# --- locate the Ghidra distribution -----------------------------------------
# Order: $GHIDRA_HOME, then a ghidra_*_PUBLIC sibling of this repo, then a
# couple of common install prefixes. Newest version wins among siblings.
find_ghidra() {
    if [[ -n "${GHIDRA_HOME:-}" && -d "$GHIDRA_HOME" ]]; then
        echo "$GHIDRA_HOME"; return 0
    fi
    local cand
    local found=""
    for cand in ../ghidra_*_PUBLIC /opt/ghidra_*_PUBLIC /usr/share/ghidra_*_PUBLIC; do
        if [[ -d "$cand" ]]; then
            found="$found$cand"$'\n'
        fi
    done
    # Newest version wins when several distributions are present.
    printf '%s' "$found" | sort -V | tail -1
}

GHIDRA="$(find_ghidra)"
if [[ -z "$GHIDRA" ]]; then
    echo "gen-classpath: no Ghidra distribution found." >&2
    echo "  Set GHIDRA_HOME=/path/to/ghidra_X.Y.Z_PUBLIC and re-run." >&2
    exit 1
fi
GHIDRA="$(cd "$GHIDRA" && pwd)"

if ! compgen -G "$GHIDRA/**/*.jar" > /dev/null && \
   ! find "$GHIDRA" -name '*.jar' -print -quit | grep -q .; then
    echo "gen-classpath: found $GHIDRA but it contains no jars." >&2
    exit 1
fi

# Java level for the JRE container. jdtls needs 21+; the Ghidra code in this
# repo targets 21 (see the openjdk-21-jdk in the chonker image).
JAVA_LEVEL="${JAVA_LEVEL:-21}"

# Source attachment is OFF by default. jdtls 1.60.0 does not act on the
# Eclipse `sourcepath` attribute: with 78 zips attached, go-to-definition on
# a Ghidra library type (e.g. ghidra.program.model.listing.Function) still
# returns nothing, and hover still attributes the type to the .jar rather
# than the source. It cost ~2min of indexing and produced no measured gain.
# The attribute is the correct Eclipse form, so it should help Eclipse/VS Code
# JDT users (the committed .project makes them auto-detect this project) --
# enable with --sources if you want that, not for jdtls.
WITH_SOURCES=0
for arg in "$@"; do
    case "$arg" in
        --sources) WITH_SOURCES=1 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "gen-classpath: unknown argument '$arg'" >&2; exit 2 ;;
    esac
done

src_attached=0

# --- collect jars -----------------------------------------------------------
# Every jar in the distribution. False positives are harmless for type
# resolution, and being exhaustive means this does not need to track which
# Ghidra module happens to export which package.
mapfile -t JARS < <(find "$GHIDRA" -name '*.jar' | sort)

if [[ ${#JARS[@]} -eq 0 ]]; then
    echo "gen-classpath: no jars under $GHIDRA" >&2
    exit 1
fi

# --- write .classpath -------------------------------------------------------
# Paths are relative to this directory so the file stays valid if the repo
# moves, and are regenerated (not committed) so a Ghidra bump is a re-run.
{
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<classpath>'
    # Source root "" covers RpcServer.java (default package). It has to
    # exclude procedures/, which is its own source root below -- otherwise
    # JDT errors with "Cannot nest ... To enable the nesting exclude".
    printf '\t<classpathentry kind="src" path="">\n'
    printf '\t\t<attributes>\n'
    printf '\t\t\t<attribute name="excluding" value="procedures"/>\n'
    printf '\t\t</attributes>\n'
    printf '\t</classpathentry>\n'
    # Source root "procedures" covers the procedures.* packages.
    printf '\t<classpathentry kind="src" path="procedures"/>\n'
    printf '\t<classpathentry kind="con" path="org.eclipse.jdt.launching.JRE_CONTAINER/org.eclipse.jdt.internal.debug.ui.launcher.StandardVMType/JavaSE-%s"/>\n' "$JAVA_LEVEL"
    local_abs="$ROOT"
    for jar in "${JARS[@]}"; do
        # Ghidra normally lives as a sibling of this repo, so most entries
        # come out as ../ghidra_X.Y.Z_PUBLIC/... rather than a bare path.
        # realpath --relative-to keeps the file valid if the repo is moved,
        # and handles both the sibling and the in-tree cases uniformly.
        rel="$(realpath --relative-to="$ROOT" "$jar")"

        # Ghidra ships compiled jars alongside a matching -src.zip (79 of
        # them, e.g. SoftwareModeling.jar / SoftwareModeling-src.zip).
        # Attaching the source archive is what lets go-to-definition land on
        # real Ghidra source instead of failing: the type resolves either
        # way, but without sourcepath there is no file to jump into.
        srczip="${jar%.jar}-src.zip"
        if [[ "$WITH_SOURCES" == "1" && -f "$srczip" ]]; then
            relsrc="$(realpath --relative-to="$ROOT" "$srczip")"
            # sourcepath is an XML attribute ON the entry, not a child
            # <attribute name="sourcepath"> element -- the latter is silently
            # ignored by JDT. Keep it relative; an absolute sourcepath next to
            # a relative path breaks launch configs (eclipse bug 258845).
            printf '\t<classpathentry kind="lib" path="%s" sourcepath="%s"/>\n' \
                "$rel" "$relsrc"
            src_attached=$((src_attached + 1))
        else
            printf '\t<classpathentry kind="lib" path="%s"/>\n' "$rel"
        fi
    done
    printf '\t<classpathentry kind="output" path="bin"/>\n'
    echo '</classpath>'
} > .classpath

# --- write .project ---------------------------------------------------------
# Only if absent: this one is stable, carries no Ghidra version, and is
# harmless (and useful) to commit so Eclipse/VS Code/JDT users auto-detect
# the project without running this script.
if [[ ! -f .project ]]; then
    cat > .project <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<projectDescription>
	<name>ghidra-rpc-server</name>
	<comment></comment>
	<projects>
	</projects>
	<buildSpec>
		<buildCommand>
			<name>org.eclipse.jdt.core.javaw.builder</name>
			<arguments>
			</arguments>
		</buildCommand>
	</buildSpec>
	<natures>
		<nature>org.eclipse.jdt.core.javanature</nature>
	</natures>
</projectDescription>
EOF
    echo "gen-classpath: wrote .project (new)"
fi

echo "gen-classpath: Ghidra   = $GHIDRA"
echo "gen-classpath: jars     = ${#JARS[@]}"
echo "gen-classpath: sources  = ${src_attached} attached"
echo "gen-classpath: wrote    = $ROOT/.classpath"
echo "gen-classpath: now run  /reload-plugins --force in Claude Code"
