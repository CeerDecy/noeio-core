#!/usr/bin/env bash

# version.sh -- keep every version string in the noeio workspace in sync with version.txt.
#
# version.txt is the single source of truth. Run with -c to verify the repo is
# consistent (used by CI), or with -u to bump and propagate a new version.

set -uo pipefail

# macOS ships BSD sed, which needs an explicit (empty) suffix for -i.
sed_inplace()
{
    if sed --version > /dev/null 2>&1; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

check_file_version()
{
    FILE=$1
    LINE_PATTERN=$2
    VERSION_STRING=$3

    echo "Check $FILE"

    CORRECT_VERSION=$(grep "$LINE_PATTERN" "$FILE" | grep "$VERSION_STRING")
    if [ "$CORRECT_VERSION" == "" ]; then
    echo "    Needs update: $FILE"
    echo "        To ensure all files match version.txt, run: version.sh -u -s"
    return 1
    else
    echo "    Verified update: $FILE ($CORRECT_VERSION)"
    fi
    return 0
}

check_twoline_version()
{
    FILE=$1
    LINE1_PATTERN=$2
    VERSION_STRING=$3

    echo "Check $FILE ($LINE1_PATTERN :: $VERSION_STRING)"

    CORRECT_VERSION=$(grep "$LINE1_PATTERN" -A 1 "$FILE" | grep "$VERSION_STRING")
    if [ "$CORRECT_VERSION" == "" ]; then
    echo "    Needs update: $FILE"
    echo "        To ensure all files match version.txt, run: version.sh -u -s"
    return 1
    else
    echo "    Verified update: $FILE ($CORRECT_VERSION)"
    fi
    return 0
}

update_file_version()
{
    FILE=$1
    LINE_PATTERN=$2
    NEW_LINE=$3

    echo "Update $FILE [$LINE_PATTERN] => [$NEW_LINE]"
    sed_inplace "s/$LINE_PATTERN/$NEW_LINE/g" "$FILE"
    return $?
}

BASEDIR=$(dirname "$0")

# Workspace members carrying their own `version = "x.y.z"` in Cargo.toml.
CARGO_PROJECTS="noeio noeio-common noeio-derp noeio-proto noeio-net-route"

CHECK=1
SAME=0
UPDATE=0
MAJOR=0
MINOR=0
PATCH=1

usage()
{
    echo "Usage: version.sh [-c] [-u] [-s] [-m|-n|-p]"
    echo "    -c checks repo versions to ensure they are set properly (default)"
    echo "    -u increments versions depending on option chosen"
    echo "    -s if -c is specified, skips requirement of changed version.txt."
    echo "       if -u is specified, updates all files to reflect version.txt."
    echo "    -m increments major version and sets minor and patch to 0"
    echo "    -n increments minor version and sets patch to 0"
    echo "    -p increments patch version (default)"
}

while getopts umnpcsh option
do
case "${option}" in
u) UPDATE=1
   CHECK=0;;
m) MAJOR=1;;
n) MINOR=1;;
p) PATCH=1;;
c) CHECK=1
   UPDATE=0;;
s) SAME=1;;
h) usage
   exit 0;;
*) usage
   exit 1;;
esac
done

if [ ! -f "$BASEDIR/version.txt" ]; then
    echo "Missing $BASEDIR/version.txt"
    exit 1
fi

if [ "$CHECK" == "1" ]; then
    VERSION=$(cat "$BASEDIR/version.txt")

    if [ "$SAME" != "1" ]; then
        echo "Verify that $BASEDIR/version.txt changed from main"
        git fetch origin main > /dev/null 2>&1
        if [ "$( git diff origin/main -- "$BASEDIR/version.txt" | wc -l | grep -v '^ *0$' )" == "" ]; then
        echo "    Needs update: version.txt"
        echo "       For non-breaking, minor changes (including bugs), run: version.sh -u -p"
        echo "       For non-breaking, new features, run: version.sh -u -n"
        echo "       For major breaking changes, run: version.sh -u -m"
        exit 1
        else
        echo "    Verified update: version.txt"
        fi
    fi

    echo "Check $BASEDIR/version.txt is MAJOR.MINOR.PATCH"
    if [ "$( echo "$VERSION" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' )" == "" ]; then
    echo "    Incorrect format: version.txt ($VERSION)"
    exit 1
    else
    echo "    Verified format: $BASEDIR/version.txt ($VERSION)"
    fi

    TOML_VERSION_PATTERN="^version = "
    TOML_VERSION="\"$VERSION\""
    for CARGO_PROJECT in $CARGO_PROJECTS
    do
        check_file_version "$BASEDIR/$CARGO_PROJECT/Cargo.toml" "$TOML_VERSION_PATTERN" "$TOML_VERSION"
        if [ "$?" -eq "1" ]; then exit 1; fi
    done

    # Cargo.lock is gitignored, so it is only checked when present locally.
    if [ -f "$BASEDIR/Cargo.lock" ]; then
        CARGO_LOCK_VERSION="^version = \"$VERSION\"$"
        for CARGO_PROJECT in $CARGO_PROJECTS
        do
            check_twoline_version "$BASEDIR/Cargo.lock" "^name = \"$CARGO_PROJECT\"$" "$CARGO_LOCK_VERSION"
            if [ "$?" -eq "1" ]; then exit 1; fi
        done
    else
        echo "Skip $BASEDIR/Cargo.lock (not present)"
    fi

    echo "All versions match $VERSION"

elif [ "$UPDATE" == "1" ]
then
    OLD_VERSION=$(cat "$BASEDIR/version.txt")

    if [ "$( echo "$OLD_VERSION" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' )" == "" ]; then
        echo "Incorrect format in version.txt ($OLD_VERSION), expected MAJOR.MINOR.PATCH"
        exit 1
    fi

    if [ "$SAME" != "1" ]; then
        if [ "$MAJOR" == "1" ]; then
            NEW_VERSION="$( echo "$OLD_VERSION" | awk -F '.' '{print $1 + 1}' ).0.0"
        elif [ "$MINOR" == "1" ]; then
            NEW_VERSION="$( echo "$OLD_VERSION" | awk -F '.' '{print $1}' ).$( echo "$OLD_VERSION" | awk -F '.' '{print $2 + 1}' ).0"
        elif [ "$PATCH" == "1" ]; then
            NEW_VERSION="$( echo "$OLD_VERSION" | awk -F '.' '{print $1}' ).$( echo "$OLD_VERSION" | awk -F '.' '{print $2}' ).$( echo "$OLD_VERSION" | awk -F '.' '{print $3 + 1}' )"
        fi
    else
        NEW_VERSION=$OLD_VERSION
    fi
    echo "Updating to version: $NEW_VERSION"

    TOML_VERSION_PATTERN="^version = .*"
    TOML_VERSION_LINE="version = \"$NEW_VERSION\""
    for CARGO_PROJECT in $CARGO_PROJECTS
    do
        update_file_version "$BASEDIR/$CARGO_PROJECT/Cargo.toml" "$TOML_VERSION_PATTERN" "$TOML_VERSION_LINE"
        if [ "$?" -ne "0" ]; then exit 1; fi
    done

    echo "$NEW_VERSION" > "$BASEDIR/version.txt"

    # Refresh Cargo.lock so the workspace member entries pick up the new version.
    if [ -f "$BASEDIR/Cargo.lock" ]; then
        cargo update --workspace --offline > /dev/null 2>&1 || cargo update --workspace
        if [ "$?" -ne "0" ]; then
            echo "Failed to update Cargo.lock, run 'cargo update --workspace' manually"
            exit 1
        fi
    fi

    echo "Updated to version: $NEW_VERSION"
fi

exit 0
