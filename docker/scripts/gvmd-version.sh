#!/usr/bin/env bash

extract_gvmd_version() {
  awk '{
    for (field = 1; field <= NF; field++) {
      if ($field ~ /^[0-9]+\.[0-9]+\.[0-9]+(~dev[0-9]+)?$/) {
        print $field
        exit
      }
    }
  }' <<< "${1:?gvmd version output is required}"
}
