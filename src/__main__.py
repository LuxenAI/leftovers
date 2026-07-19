from leftovers.cancellation import install_cancellation_handlers
from leftovers.cli import main

restore_cancellation_handlers = install_cancellation_handlers()
try:
    status = main()
except KeyboardInterrupt:
    status = 130
finally:
    restore_cancellation_handlers()

raise SystemExit(status)
