#!/usr/bin/env bash

echo ''
echo "--------Parent: $PPID"
cat /proc/$PPID/status | grep -E 'Sig.+'

echo "--------Child: $BASHPID"
cat /proc/$BASHPID/status | grep -E 'Sig.+'

echo ''

kill -USR1 $PPID
kill -USR2 $PPID

sleep 15

echo ''