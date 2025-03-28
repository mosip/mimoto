CREATE DATABASE inji_mimoto
	ENCODING = 'UTF8' 
	LC_COLLATE = 'en_US.UTF-8' 
	LC_CTYPE = 'en_US.UTF-8' 
	TABLESPACE = pg_default 
	OWNER = postgres
	TEMPLATE  = template0;

COMMENT ON DATABASE mosip_idp IS 'mimoto related data is stored in this database';

\c inji_mimoto postgres

DROP SCHEMA IF EXISTS mimoto CASCADE;
CREATE SCHEMA mimoto;
ALTER SCHEMA mimoto OWNER TO postgres;
ALTER DATABASE inji_mimoto SET search_path TO mimoto,pg_catalog,public;

