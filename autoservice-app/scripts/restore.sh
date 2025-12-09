#!/bin/bash
psql -U postgres autoservice < backup.sql
echo "Database restored"
