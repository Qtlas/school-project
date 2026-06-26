# Football Explorer

A desktop application to explore a football database through a graphical interface. It lets you run pre-built SQL queries on real match, player, and club data without writing any SQL yourself.

## What it does

The app connects to a local PostgreSQL database and exposes a set of queries organized by complexity. You pick a query from the sidebar, fill in optional parameters, and see the results in a table.

Queries are split into four categories:

- **Simple**: clubs by league, players by nationality, draws, tall strikers
- **Intermediate**: standings at a given matchday, clubs by goals scored, matches in large stadiums
- **Complex**: average goals per championship, market value rankings, home win rates, top possession
- **Tables**: raw view of every table in the database

## Database structure

The database is called `football` and contains the following tables:

- `CHAMPIONNAT` — leagues (name, country, number of clubs)
- `SAISON` — seasons linked to a league
- `CLUB` — clubs with stadium info and founding year
- `JOUEUR` — players with position, physical stats, and nationality
- `MATCH_FOOTBALL` — match results with scores and matchday
- `STATS_MATCH_EQUIPE` — per-match team stats like possession
- `CLASSEMENT` — standings per matchday
- `VALEUR_MARCHANDE` — player market values over time

## Requirements

- Python 3
- PostgreSQL
- Python packages: `psycopg2`, `tkinter` (usually bundled with Python)

Install dependencies:

```bash
pip install psycopg2-binary
```

## Setup

1. Make sure PostgreSQL is running with a `postgres` user.
2. Run the setup script to create and populate the database:

```bash
bash run.sh
```

This will drop and recreate the `football` database, then run `init.sql` and `traitements.sql`.

3. Open `main.py` and set your database password if needed:

```python
DB = {
    "host": "localhost",
    "port": 5432,
    "dbname": "football",
    "user": "postgres",
    "password": ""  # add your password here
}
```

4. Launch the app:

```bash
python main.py
```

## File overview

| File | Description |
|---|---|
| `init.sql` | Creates all tables and populates them with data |
| `traitements.sql` | Runs all queries with their default parameters |
| `requetes.json` | Defines all queries shown in the app (SQL + parameters) |
| `main.py` | The graphical interface |
| `run.sh` | Setup script to initialize the database |
