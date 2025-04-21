START TRANSACTION;

CREATE TABLE
  IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    password bytea NOT NULL,
    salt bytea NOT NULL,
    UNIQUE(username)
  );

CREATE TABLE
  IF NOT EXISTS login_and_passes (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    login text NOT NULL,
	  password text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS login_and_passes_for_update (
    id SERIAL PRIMARY KEY,
    data_id integer,
    username text NOT NULL,
    login text NOT NULL,
	  password text NOT NULL
  );
  
CREATE TABLE
  IF NOT EXISTS texts (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    text text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS texts_for_update (
    id SERIAL PRIMARY KEY,
    data_id integer,
    username text NOT NULL,
    text text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS bytes (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    bytes text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS bytes_for_update (
    id SERIAL PRIMARY KEY,
    data_id integer,
    username text NOT NULL,
    bytes text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS bank_cards (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    number text NOT NULL,
	  card_holder_name text NOT NULL,
    expiration_date text NOT NULL,
    cvv text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS bank_cards_for_update (
    id SERIAL PRIMARY KEY,
    data_id integer,
    username text NOT NULL,
    number text NOT NULL,
	  card_holder_name text NOT NULL,
    expiration_date text NOT NULL,
    cvv text NOT NULL
  );

COMMIT;