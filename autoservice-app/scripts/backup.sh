#!/bin/bash
pg_dump -U postgres autoservice > backup.sql
echo "Backup completed"
