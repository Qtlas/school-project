#!/bin/bash

DB_NAME="football"
DB_USER="postgres"

psql -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE);"

psql -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME;"

psql -U "$DB_USER" -d "$DB_NAME"  -f init.sql

psql -U "$DB_USER" -d "$DB_NAME"  -f traitements.sql

echo "Terminé"