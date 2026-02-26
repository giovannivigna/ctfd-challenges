# fuzzbiz3

Crash the program and get the flag.

Normally msg->data is initialized correctly.
If the input is exactly 64 bytes long, msg->data is set to NULL, and msg->flag is set to 1.
In process_message(), we dereference msg->data[0] without checking.
This triggers a segmentation fault (NULL dereference) if msg->data is NULL.

