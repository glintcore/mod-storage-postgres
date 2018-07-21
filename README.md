
PostgreSQL Storage Module
=========================

Copyright (C) 2017-2018 Index Data ApS.  This software is distributed under
the terms of the Apache License, Version 2.0.  See the file
[LICENSE](https://github.com/glintcore/mod-storage-postgres/blob/master/LICENSE)
for more information.


Overview
--------

This is a module for [Glint](https://glintcore.net) which allows the server
to store data in a PostgreSQL database.


System requirements
-------------------

This module has the same system requirements as the [Glint
server](https://github.com/glintcore/glint-server).


Installing the module
---------------------

To download and compile the module:

```shell
$ go get -u -v github.com/glintcore/mod-storage-postgres/...
$ go build -buildmode=plugin mod-storage-postgres.go
```

The compiled library file, `mod-storage-postgres.so`, should appear in
`$GOPATH/src/github.com/glintcore/mod-storage-postgres/`.

To enable the module, add its full path to the server configuration file
under the storage section:

```ini
[storage]
module = /path/to/mod-storage-postgres.so
```

Then restart the server.


