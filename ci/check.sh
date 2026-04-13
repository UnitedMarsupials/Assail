#!/bin/sh
set -ex

# Use the same perl as spamassassin itself
SA=$(which spamassassin 2>/dev/null || true)
if [ -n "$SA" ]; then
	PERL=$(head -1 "$SA" | sed 's/^#![ ]*//' | awk '{print $1}')
else
	PERL=perl
fi

$PERL -c AI/AI.pm
