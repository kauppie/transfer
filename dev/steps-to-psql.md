# Using PostgreSQL

## Access database table via terminal.

Get container ID.

```
<docker|podman> ps
```

Attach to container.

```
<docker|podman> exec -it <container ID> bash
```

Open postgres terminal.

```
psql
```

List databases.

```
\l
```

Connect to database.

```
\c <database name>
```

Show all tables.

```
\dt
```

Execute statement. Note: use of CAPITAL case and semicolon are required. Terminal won't show errors nor execute the statement if these requirements aren't met.

```
SELECT * FROM table;
```
