Create the postgres database: 
- CREATE user emailgurus with encrypted password 'emailgurus';
- ALTER USER emailgurus CREATEDB;
- CREATE DATABASE emailgurus;
- ALTER database  emailgurus OWNER to  emailgurus;