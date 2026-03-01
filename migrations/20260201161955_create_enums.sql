-- Add migration script here
-- Create the custom types
CREATE TYPE  visibility AS ENUM ('public', 'private') ;
CREATE TYPE object_status AS ENUM ('active', 'deleted');
