#!/bin/bash
set -e

echo "Waiting for PostgreSQL to start..."
sleep 5

echo "Restoring backup.sql..."
psql -U postgres -d autoservice < /backup/backup.sql

echo "Restore completed!"
