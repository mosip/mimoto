-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------

\c :mosipdbname

GRANT CONNECT
   ON DATABASE :mosipdbname
   TO :dbuname;

GRANT USAGE
   ON SCHEMA mimoto
   TO :dbuname;

GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES
   ON ALL TABLES IN SCHEMA mimoto
   TO :dbuname;

ALTER DEFAULT PRIVILEGES IN SCHEMA mimoto
	GRANT SELECT,INSERT,UPDATE,DELETE,REFERENCES ON TABLES TO :dbuname;

