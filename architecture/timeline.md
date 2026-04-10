# SOP: Timeline Generation

## Objective
To reconstruct a chronological sequence of events based on file system artifacts to understand user activity.

## Procedure
1. **Event Extraction**: Extract Create, Modify, and Access (MAC) times for every evidence item.
2. **Event Normalization**: Convert all timestamps to ISO 8601 format.
3. **Severity Mapping**: Link event severity to the RAG classification of the source file.
4. **Sorting**: Sort all events chronologically (newest first).
5. **Clustering**: Group events that occurred within a short time window (e.g., 30 minutes) to identify "bursts" of activity.

## Tools
- `tools/timeline.py`
- Python `datetime` module

## Data Output
- `timeline` table entries in the database.
- Visual timeline representation in the UI.
