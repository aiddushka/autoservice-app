#!/bin/bash
psql -U postgres -d autoservice < /backup/backup.sql
echo "Database restored"
