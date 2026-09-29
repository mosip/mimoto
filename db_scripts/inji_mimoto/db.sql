CREATE DATABASE :dbname
	ENCODING = 'UTF8' 
	LC_COLLATE = 'en_US.UTF-8' 
	LC_CTYPE = 'en_US.UTF-8' 
	TABLESPACE = pg_default 
	OWNER = postgres
	TEMPLATE  = template0;

COMMENT ON DATABASE mosip_idp IS 'mimoto related data is stored in this database';

\c :dbname postgres

DROP SCHEMA IF EXISTS mimoto CASCADE;
CREATE SCHEMA mimoto;
ALTER SCHEMA mimoto OWNER TO postgres;
ALTER DATABASE :dbname SET search_path TO mimoto,pg_catalog,public;

