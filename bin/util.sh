#!/usr/bin/env bash

function error() {
  echo " !     $*" >&2
  exit 1
}

function topic() {
  echo "-----> $*"
}

function indent() {
  c='s/^/       /'
  case $(uname) in
	Darwin) sed -l "$c";;
	*)      sed -u "$c";;
  esac
}

export_env_dir() {
  env_dir=$1
  whitelist_regex=${2:-''}
  blacklist_regex=${3:-'^(PATH|GIT_DIR|CPATH|CPPATH|LD_PRELOAD|LIBRARY_PATH)$'}
  if [ -d "$env_dir" ]; then
    for e in $(ls $env_dir); do
      echo "$e" | grep -E "$whitelist_regex" | grep -qvE "$blacklist_regex" &&
      export "$e=$(cat $env_dir/$e)"
      :
    done
  fi
}
