-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_rest" to load this file. \quit

-- the generic crosstab function:
CREATE FUNCTION exec(text)
RETURNS integer
AS 'MODULE_PATHNAME','exec'
LANGUAGE C STABLE STRICT;

CREATE FUNCTION http_run()
RETURNS integer
AS 'MODULE_PATHNAME','http_run'
LANGUAGE C STABLE STRICT;

CREATE FUNCTION http_stop()
RETURNS integer
AS 'MODULE_PATHNAME','http_stop'
LANGUAGE C STABLE STRICT;

CREATE FUNCTION http_status()
RETURNS integer
AS 'MODULE_PATHNAME','http_status'
LANGUAGE C STABLE STRICT;
