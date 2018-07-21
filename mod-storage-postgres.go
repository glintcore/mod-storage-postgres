package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	// Blank import, temporary for PostgreSQL.
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type postgres struct {
	connstr string
}

func (pg *postgres) Open(dataSourceName string) error {
	fmt.Printf("Using mod-storage-postgres\n")
	pg.connstr = dataSourceName
	// Open database here
	return nil
}

func (pg *postgres) Close() error {
	fmt.Printf("postgres.Close()\n")
	// Close database here
	return nil
}

/////////////////////////////////////////////////////////////////////

var glintdb *sql.DB

func validatePassword(password string) error {
	// Check if all characters are ASCII printable.
	for _, r := range password {
		if r < 33 || r > 126 {
			return errors.New("Password must consist of ASCII " +
				"printable characters")
		}
	}
	// Check password length.
	if len(password) < 8 || len(password) > 32 {
		return errors.New(
			"Password must contain between 8 and 32 characters")
	}
	return nil
}

func Connect(host, port, user, password, dbname string) error {
	var info string = fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s "+
			"sslmode=disable", host, port, user, password, dbname)
	var err error
	glintdb, err = sql.Open("postgres", info)
	if err != nil {
		return err
	}
	// Ping the database to test the connection.
	err = glintdb.Ping()
	if err != nil {
		return err
	}
	return nil
}

func schemaExists() (bool, error) {
	var st *sql.Stmt
	var err error
	st, err = glintdb.Prepare(`
		select table_name
		    from information_schema.tables
		    where table_schema = 'public' and table_name = 'person';
		`)
	if err != nil {
		return false, err
	}
	defer st.Close()
	var tableName string
	err = st.QueryRow().Scan(&tableName)
	switch err {
	case nil:
		return true, nil
	case sql.ErrNoRows:
		return false, nil
	default:
		return false, err
	}
}

func LookupPassword(username string) (string, error) {
	var st *sql.Stmt
	var err error
	st, err = glintdb.Prepare(`
		select password_hash
		    from person
		    where username = $1;
		`)
	if err != nil {
		return "", err
	}
	defer st.Close()
	var password_hash string
	err = st.QueryRow(username).Scan(&password_hash)
	switch err {
	case nil:
		return password_hash, nil
	case sql.ErrNoRows:
		return "", err
	default:
		return "", err
	}
}

func Authenticate(username string, password string) (bool, error) {
	var password_hash string
	var err error
	password_hash, err = LookupPassword(username)
	if err != nil {
		return false, err
	}
	// If the database has no value for password_hash, then
	// do not allow any password to authenticate.
	if password_hash == "" {
		return false, nil
	}
	// Hash password and compare with password_hash in database.
	err = bcrypt.CompareHashAndPassword([]byte(password_hash),
		[]byte(password))
	if err != nil {
		// The password hashes did not match.
		return false, nil
	}
	return true, nil
}

func CreateTablePerson(tx *sql.Tx) error {
	var st *sql.Stmt
	var err error
	st, err = tx.Prepare(`
		create table person (
		    id bigserial not null,
		        primary key (id),
		    username text not null,
		        unique (username),
		        check (username <> ''),
		    fullname text not null default '',
		    email text not null default '',
		    password_hash text not null default '',
		    acct_disabled boolean not null default false
		);
		`)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Exec()
	if err != nil {
		return err
	}
	return nil
}

func validateAndHashPassword(password string) (string, error) {
	// Validate the new password.
	var err = validatePassword(password)
	if err != nil {
		return "", err
	}
	// Hash and salt the password.
	var hash []byte
	hash, err = bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func AddMetadata(personId int64, path string, attribute string,
	metadata string) error {

	var fileId int64
	var err error
	fileId, err = LookupFileId(personId, path)
	if err != nil {
		return err
	}

	// TODO Check that user exists in table, because update does not
	// consider 0 updates to be an error.

	var st *sql.Stmt
	st, err = glintdb.Prepare(`
		update attribute
		    set metadata = $1
		    where file_id = $2 and attr = $3;
		`)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Exec(metadata, fileId, attribute)
	if err != nil {
		return err
	}
	return nil
}

func ChangePassword(username string, password string) error {

	// TODO Check that user exists in table, because update does not
	// consider 0 updates to be an error.

	// Validate and hash password.
	var hash string
	var err error
	hash, err = validateAndHashPassword(password)
	if err != nil {
		return err
	}
	// Store in the database.
	var st *sql.Stmt
	st, err = glintdb.Prepare(`
		update person
		    set password_hash = $1
		    where username = $2;
		`)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Exec(hash, username)
	if err != nil {
		return err
	}
	return nil
}

func LookupPersonId(username string) (int64, error) {
	var st *sql.Stmt
	var err error
	st, err = glintdb.Prepare(`
		select id
		    from person
		    where username = $1;
		`)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	var id int64
	err = st.QueryRow(username).Scan(&id)
	switch err {
	case nil:
		return id, nil
	case sql.ErrNoRows:
		return 0, err
	default:
		return 0, err
	}
}

func AddPerson(username string, fullname string, email string,
	password string) error {
	// TODO Validate user characters with something similar to
	// validatePassword().
	// Validate and hash password.
	var hash string
	var err error
	hash, err = validateAndHashPassword(password)
	if err != nil {
		return err
	}
	// Store in the database.
	var st *sql.Stmt
	st, err = glintdb.Prepare(`
		insert into person (username, fullname, email, password_hash)
		values ($1, $2, $3, $4);
		`)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Exec(username, fullname, email, hash)
	if err != nil {
		return err
	}
	return nil
	// TODO Return id.
}

func LookupFileId(personId int64, path string) (int64, error) {
	var st *sql.Stmt
	var err error
	st, err = glintdb.Prepare(`
		select id
		    from file
		    where person_id = $1 and path = $2;
		`)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	var id int64
	err = st.QueryRow(personId, path).Scan(&id)
	switch err {
	case nil:
		return id, nil
	case sql.ErrNoRows:
		return 0, err
	default:
		return 0, err
	}
}

func LookupMetadata(personId int64, path string, attribute string) (string,
	error) {

	var fileId int64
	var err error
	fileId, err = LookupFileId(personId, path)
	if err != nil {
		return "", err
	}

	var st *sql.Stmt
	st, err = glintdb.Prepare(`
		select metadata
		    from attribute
		    where file_id = $1 and attr = $2;
		`)
	if err != nil {
		return "", err
	}
	defer st.Close()
	var metadata string
	err = st.QueryRow(fileId, attribute).Scan(&metadata)
	switch err {
	case nil:
		if metadata == "" {
			return "", nil
		}
		return "{" + metadata + "}", nil
	case sql.ErrNoRows:
		return "", err
	default:
		return "", err
	}
}

func LookupData(person_id int64, path string) (string, error) {
	var st *sql.Stmt
	var err error
	st, err = glintdb.Prepare(`
		select data
		    from file
		    where person_id = $1 and path = $2;
		`)
	if err != nil {
		return "", err
	}
	defer st.Close()
	var data string
	err = st.QueryRow(person_id, path).Scan(&data)
	switch err {
	case nil:
		return data, nil
	case sql.ErrNoRows:
		return "", err
	default:
		return "", err
	}
}

func LookupDataList(person_id int64) (string, error) {
	var st *sql.Stmt
	var err error
	st, err = glintdb.Prepare(`
		select path
		    from file
		    where person_id = $1;
		`)
	if err != nil {
		return "", err
	}
	defer st.Close()

	var rows *sql.Rows
	rows, err = st.Query(person_id)

	var b strings.Builder
	fmt.Fprintf(&b, "name\n")
	for rows.Next() {
		var dataName string
		err = rows.Scan(&dataName)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s\n", dataName)
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func AddFile(person_id int64, path string, data string) (int64, error) {
	// Store in the database.
	var st *sql.Stmt
	var err error
	st, err = glintdb.Prepare(`
                insert into file (person_id, path, data)
                values ($1, $2, $3)
                returning id;
		`)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	var id int64
	err = st.QueryRow(person_id, path, data).Scan(&id)
	switch err {
	case nil:
		return id, nil
	case sql.ErrNoRows:
		return 0, err
	default:
		return 0, err
	}
}

func deleteFromAttribute(fileId int64) error {
	var st *sql.Stmt
	var err error
	st, err = glintdb.Prepare(`
		delete from attribute where file_id = $1;
		`)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Exec(fileId)
	if err != nil {
		return err
	}
	return nil
}

func deleteFromFile(id int64) error {
	var st *sql.Stmt
	var err error
	st, err = glintdb.Prepare(`
		delete from file where id = $1;
		`)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Exec(id)
	if err != nil {
		return err
	}
	return nil
}

func DeleteFile(personId int64, path string) error {

	var fileId int64
	var err error
	fileId, err = LookupFileId(personId, path)
	if err != nil {
		return err
	}

	if err = deleteFromAttribute(fileId); err != nil {
		return err
	}

	if err = deleteFromFile(fileId); err != nil {
		return err
	}

	return nil
}

func AddAttributes(file_id int64, attrs []string) error {
	var x int
	for x = range attrs {
		// Store in the database.
		var st *sql.Stmt
		var err error
		st, err = glintdb.Prepare(`
                        insert into attribute
                            (file_id, attr)
                            values ($1, $2)
                            returning id;
		`)
		if err != nil {
			return err
		}
		defer st.Close()
		var id int64
		err = st.QueryRow(file_id, attrs[x]).Scan(&id)
		switch err {
		case nil:
			continue
		case sql.ErrNoRows:
			return err
		default:
			return err
		}
	}
	return nil
}

func CreateTableAttribute(tx *sql.Tx) error {
	var st *sql.Stmt
	var err error
	st, err = tx.Prepare(`
		create table attribute (
		    id bigserial not null,
		        primary key (id),
		    file_id bigint not null,
		        foreign key (file_id) references file (id),
		    attr text not null,
		        check (attr <> ''),
		    unique (file_id, attr),
		    metadata text not null default ''
		);
		`)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Exec()
	if err != nil {
		return err
	}
	return nil
}

func CreateTableFile(tx *sql.Tx) error {
	var st *sql.Stmt
	var err error
	st, err = tx.Prepare(`
		create table file (
		    id bigserial not null,
		        primary key (id),
		    person_id bigint not null,
		        foreign key (person_id) references person (id),
		    path text not null,
		        check (path <> ''),
		    unique (person_id, path),
		    data text not null,
		        check (data <> '')
		);
		`)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Exec()
	if err != nil {
		return err
	}
	return nil
}

func CreateSchema() error {
	log.Print("Initializing database")
	var tx *sql.Tx
	var err error
	tx, err = glintdb.Begin()
	if err != nil {
		return err
	}
	err = CreateTablePerson(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = CreateTableFile(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = CreateTableAttribute(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func Setup() error {
	// Open the database connection pool.
	/*
		var err = Connect(host, port, user, password, dbname)
		if err != nil {
			return fmt.Errorf("Unable to connect to database: %v", err)
		}
	*/
	// Check if the schema appears to exist, and create it if not.
	schema, err := schemaExists()
	if err != nil {
		return err
	}
	if !schema {
		err = CreateSchema()
		if err != nil {
			return err
		}
	}
	return nil
}

//////////////////////////////////////////

var StorageModule postgres
