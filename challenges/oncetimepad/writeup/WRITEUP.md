# oncetimepad

Produces a string encrypted with a one-time pad.
The seed for the random number generator is the current epoch.
By parsing the date printed at the beginning and using it as a seed, it is possible to obtain the pad and therefore the message.

