-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------

\c inji_mimoto

GRANT CONNECT
   ON DATABASE inji_mimoto
   TO mimotouser;

GRANT USAGE
   ON SCHEMA mimoto
   TO mimotouser;

GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES
   ON ALL TABLES IN SCHEMA mimoto
   TO mimotouser;

ALTER DEFAULT PRIVILEGES IN SCHEMA mimoto
	GRANT SELECT,INSERT,UPDATE,DELETE,REFERENCES ON TABLES TO mimotouser;

