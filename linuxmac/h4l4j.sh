#!/bin/bash

# based on https://github.com/rubo77/log4j_checker_beta

# needs locate to be installed, be sure to be up-to-date with
# sudo updatedb

# example usage:
# bash h4l4j.sh -p 3 >>/var/log/h4l4j.log 2>&1
# regular expression, check the following packages:
PACKAGES='solr\|elastic\|log4j'

# defaults
# used if not specified on the command line
# -d '/opt/McAfee/bin' -c 6
MCAFEE_DIR='/opt/McAfee/agent/bin' # + [ '/maconfig -custom -prop8 "message" | '/cmdagent -p' ]
CUSTOM_PROP=''  # which custom prop to use for 

# parse command line arguments and override if provided

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      echo "usage:"
      echo "h4l4j.sh [args...] [SHA256_HASHES_URL]"
      echo "  (-h | --help)                                      # This usage message"
      echo "  (-d | --directory) <mcafee/install/directory>      # The mcafee installation directory (/opt/McAfee/agent/bin)"
      echo "  (-p | --prop) <1..8>                               # The custom props slot to use for the result"
      echo 
      exit 0
      ;;
    -d|--directory)
      MCAFEE_DIR="$2"
      shift # past argument
      shift # past value
      ;;
    -p|--prop)
      CUSTOM_PROP="$2"
      shift # past argument
      shift # past value
      ;;
    -*|--*)
      echo "Unknown option $1 try '-h'"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

# Set this if you have a download for sha256 hashes
SHA256_HASHES_URL="$1"

RED="\033[0;31m"; GREEN="\033[32m"; YELLOW="\033[1;33m"; ENDCOLOR="\033[0m"
# if you don't want colored output, set the variables to empty strings:
# RED=""; GREEN=""; YELLOW=""; ENDCOLOR=""

function warning() {
  printf "${RED}[WARNING] %s${ENDCOLOR}\n" "$1" >&2
}

function information() {
  printf "${YELLOW}[INFO] %s${ENDCOLOR}\n" "$1"
}

function ok() {
  printf "${GREEN}[INFO] %s${ENDCOLOR}\n" "$1"
}

if [ "$CUSTOM_PROP" = "" ]; then
  warning "you need to provide a custom prop number between 1 and 8 with the -p <num> argument"
  exit 1
fi

if [ "$SHA256_HASHES_URL" = "" ]; then
  information "using default hash file. If you want to use other hashes, provide another URL (try '-h' for usage information)"
  SHA256_HASHES_URL="https://raw.githubusercontent.com/McAfeeAndrew/h4l4j/main/hashes-pre-cve.txt"
fi

export LANG=

function locate_log4j() {
  if [ "$(command -v locate)" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
      # Mac OSX
      locate -i log4j
    else
      locate -ei log4j
    fi
  else
    find \
      /var /etc /usr /opt /lib* \
      -iname "*log4j*" 2>&1 \
      | grep -v '^find:.* Permission denied$' \
      | grep -v '^find:.* No such file or directory$'
  fi
}

function find_jar_files() {
  find \
    /var /etc /usr /opt /lib* \
    -iname "*.jar" -o -iname "*.war" -o -iname "*.ear" 2>&1 \
    | grep -v '^find:.* Permission denied$' \
    | grep -v '^find:.* No such file or directory$'
}

# check root user
if [ $USER != root ]; then
  warning "You have no root-rights. Not all files will be found."
fi

dir_temp_hashes=$(mktemp -d --suffix _log4jscan)
file_temp_hashes="$dir_temp_hashes/vulnerable.hashes"
ok_hashes=
if [[ -n $SHA256_HASHES_URL && $(command -v wget) ]]; then
  wget  --max-redirect=0 --tries=2 -O "$file_temp_hashes.in" -- "$SHA256_HASHES_URL"
elif [[ -n $SHA256_HASHES_URL && $(command -v curl) ]]; then
  curl --globoff -f "$SHA256_HASHES_URL" -o "$file_temp_hashes.in"
fi
if [[ $? = 0 && -s "$file_temp_hashes.in" ]]; then
  cat "$file_temp_hashes.in" | cut -d" " -f1 | sort | uniq  > "$file_temp_hashes"
  ok_hashes=1
  information "Downloaded vulnerable hashes from $SHA256_HASHES_URL"
fi

WARN = "Warning:"
# INFO = "Info:"

# first scan: use locate
echo
information "Looking for files containing log4j..."
if [ "$(command -v locate)" ]; then
  information "using locate, which could be using outdated data. besure to have called updatedb recently"
fi
OUTPUT="$(locate_log4j | grep -iv log4js | grep -v log4j_checker_beta)"
if [ "$OUTPUT" ]; then
  warning "Maybe vulnerable, those files contain the name:"
  printf "%s\n" "$OUTPUT"
  WARN="${WARN} Files Containing 'log4j'."
else
  ok "No files containing log4j"
  # INFO="${INFO} No files containing log4j."
fi

# second scan: use package manager
echo
information "Checking installed packages: ($PACKAGES)"
if [ "$(command -v yum)" ]; then
  # using yum
  OUTPUT="$(yum list installed | grep -i $PACKAGES | grep -iv log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, yum installed packages:"
    WARN="${WARN} yum installed log4j packages."
    printf "%s\n" "$OUTPUT"
  else
    ok "No yum packages found"
    # INFO="${INFO} No yum packages found."
  fi
fi
if [ "$(command -v dpkg)" ]; then
  # using dpkg
  OUTPUT="$(dpkg -l | grep -i $PACKAGES | grep -iv log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, dpkg installed packages:"
    WARN="${WARN} dpkg installed log4j packages."
    printf "%s\n" "$OUTPUT"
  else
    ok "No dpkg packages found"
    # INFO="${INFO} No dpkg packages found."
  fi
fi

# third scan: check for "java" command
echo
information "Checking if Java is installed..."
JAVA="$(command -v java)"
if [ "$JAVA" ]; then
  warning "Java is installed"
  WARN="${WARN} Java is installed."
  information "   Java applications often bundle their libraries inside binary files,"
  information "   so there could be log4j in such applications."
else
  ok "Java is not installed"
  # INFO="${INFO} Java is not installed."
fi

# perform best-effort find call for all jars and optionally check against hashes
echo
information "Analyzing JAR/WAR/EAR files..."
if [ $ok_hashes ]; then
  information "Also checking hashes"
fi
COUNT=0
COUNT_FOUND=0
if [ "$(command -v unzip)" ]; then
  # inject find_jar_files at the end of the while loop to prevent extra shell
  while read -r jar_file; do
    unzip -l "$jar_file" 2> /dev/null \
      | grep -q -i "log4j" && \
      echo && \
      warning "[$COUNT - contains log4j files] $jar_file"
    COUNT=$(($COUNT + 1))
    if [ $ok_hashes ]; then
      base_name=$(basename "$jar_file")
      dir_unzip="$dir_temp_hashes/java/$COUNT""_$( echo "$base_name" | tr -dc '[[:alpha:]]')"
      mkdir -p "$dir_unzip"
      unzip -qq -DD "$jar_file" '*.class' -d "$dir_unzip" 2> /dev/null \
        && find "$dir_unzip" -type f -not -name "*"$'\n'"*" -iname '*.class' -exec sha256sum "{}" \; \
        | cut -d" " -f1 | sort | uniq > "$dir_unzip/$base_name.hashes";
      if [ -f "$dir_unzip/$base_name.hashes" ]; then
        num_found=$(comm -12 "$file_temp_hashes" "$dir_unzip/$base_name.hashes" | wc -l)
      else
        num_found=0
      fi
      if [[ -n $num_found && $num_found != 0 ]]; then
        echo
        warning "[$COUNT - vulnerable binary classes] $jar_file"
        COUNT_FOUND=$(($COUNT_FOUND + 1))
      else
        printf "."
        # ok "[$COUNT] No .class files with known vulnerable hash found in $jar_file at first level."
      fi
      # delete temp folder containing the extracted java files
      rm -rf -- "$dir_unzip"
    fi
  done <<<$(find_jar_files)
  echo
  if [[ $COUNT -gt 0 ]]; then
    information "Found $COUNT files in unpacked binaries containing the string 'log4j' with $COUNT_FOUND vulnerabilities"
    if [[ $COUNT_FOUND -gt 0 ]]; then
      warning "Found $COUNT_FOUND vulnerabilities in unpacked binaries"
      WARN="Found $COUNT_FOUND vulnerabilities in unpacked binaries."
    fi
  fi
else
  information "Cannot look for log4j inside JAR/WAR/EAR files (unzip not found)"
fi

# delete temp folder containing $file_temp_hashes
[ $ok_hashes ] && rm -rf -- "$dir_temp_hashes"

information "_________________________________________________"
if [ "$JAVA" == "" ]; then
  warning "Some apps bundle the vulnerable library in their own compiled package, so even if 'java' is not installed, one of the applications could still be vulnerable."
fi

echo
warning "This script does not guarantee that you are not vulnerable, but is a strong hint."
echo

${MCAFEE_DIR}/maconfig -custom "-prop${CUSTOM_PROP}" "${WARN}"
${MCAFEE_DIR}/cmdagent -p