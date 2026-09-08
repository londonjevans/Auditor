"""Fixed finite synthetic CLI replies; no runtime, container, network or input execution."""

import os
import sys
import time

mode = sys.argv[1]
if mode == "absent":
    pass
elif mode == "present":
    os.write(1, b"a" * 64 + b"\n")
elif mode == "error":
    os.write(2, b"synthetic runtime unavailable\n")
    sys.exit(125)
elif mode == "warning":
    os.write(2, b"synthetic incomplete query warning\n")
elif mode == "ambiguous":
    os.write(1, b"b" * 64 + b"\n")
elif mode == "stdout_limit":
    os.write(1, b"x" * 4097)
    time.sleep(2)
elif mode == "stderr_limit":
    os.write(2, b"x" * 4097)
    time.sleep(2)
elif mode == "timeout":
    time.sleep(2)
elif mode == "descendant":
    if os.fork() == 0:
        for descriptor in (0, 1, 2):
            os.close(descriptor)
        time.sleep(2)
        os._exit(0)
else:
    sys.exit(23)
