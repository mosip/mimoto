-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_mimoto
-- Table Name : user_metadata
-- Purpose    : User Metadata table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS user_metadata (
    id VARCHAR(36) PRIMARY KEY,  -- Primary key for the table
    provider_subject_id VARCHAR(255) UNIQUE NOT NULL,  -- Unique identifier for the provider subject
    identity_provider VARCHAR(255) UNIQUE NOT NULL,  -- Unique identifier for the identity provider
    display_name TEXT NOT NULL,  -- Display name of the user
    profile_picture_url TEXT,  -- URL of the user's profile picture
    phone_number TEXT,  -- Phone number of the user
    email TEXT NOT NULL,  -- Email of the user (Required field)
    created_at TIMESTAMP DEFAULT now(),  -- Timestamp of record creation (defaults to current time)
    updated_at TIMESTAMP DEFAULT now()  -- Timestamp of last update (defaults to current time)
);

COMMENT ON TABLE user_metadata IS 'User Metadata: Contains details about the user such as identity provider, contact details, and display name';

COMMENT ON COLUMN user_metadata.id IS 'Primary Key: Unique identifier for the user metadata';
COMMENT ON COLUMN user_metadata.provider_subject_id IS 'Provider Subject ID: Unique identifier for the subject assigned by the identity provider';
COMMENT ON COLUMN user_metadata.identity_provider IS 'Identity Provider: The identity provider associated with the user';
COMMENT ON COLUMN user_metadata.display_name IS 'Display Name: The name shown to other users';
COMMENT ON COLUMN user_metadata.profile_picture_url IS 'Profile Picture URL: The URL link to the user\'s profile picture';
COMMENT ON COLUMN user_metadata.phone_number IS 'Phone Number: User\'s phone number, if available';
COMMENT ON COLUMN user_metadata.email IS 'Email: User\'s email address';
COMMENT ON COLUMN user_metadata.created_at IS 'Created At: The date and time when the metadata was created';
COMMENT ON COLUMN user_metadata.updated_at IS 'Updated At: The date and time when the metadata was last updated';
