# webifile

The application lets authenticated users create a document by reading a server-side file:

- Endpoint: `POST /documentfile`
- It opens `"/tmp/app/{filename}"` without normalizing or restricting `filename`.

Because `filename` is not sanitized, it is vulnerable to **directory traversal**. Since the flag is stored at `/flag`, a user can request:

`../../../../flag`

from the `/tmp/app/` base directory, and the resulting document will contain the flag contents.

## Steps

1. Register a new user.
2. Log in.
3. Create a document from the file `../../../../flag`.
4. Read the created document and extract the flag.

