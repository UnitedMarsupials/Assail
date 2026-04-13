#!/bin/sh
set -ex

# Use the same perl as spamassassin itself
SA=$(which spamassassin)
PERL=$(head -1 "$SA" | sed 's/^#![ ]*//' | awk '{print $1}')

$PERL -c AI/AI.pm
