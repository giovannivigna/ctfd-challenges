## sleak

This service stores heap-allocated nodes in a linked list. Each node contains a secret key, some data, and a function pointer used to "encrypt/decrypt" the data.

When you **print** a node, the service leaks:
- The address on the stack that holds the linked-list head pointer (`Node list @ ...`)
- The node address and the address/value of every field (including the function pointer into `.text`)
- An **Execution ID** which equals `StackBase - NodeListStackSlotPtr`

On **quit**, the service asks for the beginning of:
- The stack
- The heap
- The `.text` section

To solve, print a node and use the leaks to compute:
- `stack_base = (Node list @ ptr) + (Execution ID)`
- `heap_base  = node_ptr & ~0xfff`
- `text_base  = crypt_fn_ptr & ~0xfff`

Then provide those three base addresses when quitting to get `/flag`.

