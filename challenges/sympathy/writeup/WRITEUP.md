# sympathy Write-up

This challenge is a file reading service that allows users to list and read files from a `./files` directory.

The service has a path traversal vulnerability that can be exploited to read files outside the intended directory, including the flag file at `/flag`.

## Vulnerability Analysis

Looking at the source code in `sympathy.c`, the service has a "Read a file" option that:
1. Takes user input for a filename
2. Checks if the input contains `".."` to prevent path traversal
3. If the input starts with byte `0x90`, it base64-decodes the rest of the input
4. Constructs a filepath as `./files/{decoded_filename}` and reads it

The vulnerability is that the check for `".."` only works on the raw input string. However, if we base64-encode a path traversal payload (like `../../../../flag`) and prepend it with `0x90`, the check will pass because the raw input doesn't contain `".."` - it's base64-encoded.

## Exploitation

The exploit works by:
1. Base64-encoding a path traversal payload: `../../../../flag`
2. Prepending the byte `0x90` to trigger the base64 decoding path
3. Sending this payload when prompted for a filename
4. The service decodes the base64, constructs the path `./files/../../../../flag`, which resolves to `/flag`
5. The service then reads and displays the flag

The exploit script automates this process by connecting to the service, selecting option 2 (Read a file), and sending the crafted payload.

