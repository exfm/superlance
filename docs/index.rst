superlance plugins for supervisor
=================================

Superlance is a package of plugin utilities for monitoring and
controlling processes that run under `supervisor
<http://supervisord.org>`_.

Currently, it provides three plugins:

:command:`httpok`
    This plugin is meant to be used as a supervisor event listener,
    subscribed to ``TICK_*`` events.  It tests that a given child process
    which must in the ``RUNNING`` state, is viable via an HTTP ``GET``
    request to a configured URL.  If the request fails or times out,
    :command:`httpok` will restart the "hung" child process.

:command:`crashmail`
    This plugin is meant to be used as a supervisor event listener,
    subscribed to ``PROCESS_STATE_EXITED`` events.  It email a user when
    a process enters the ``EXITED`` state unexpectedly.

:command:`memmon`
    This plugin is meant to be used as a supervisor event listener,
    subscribed to ``TICK_*`` events.  It monitors memory usage for configured
    child processes, and restarts them when they exceed a configured
    maximum size.


Contents:

.. toctree::
   :maxdepth: 2

   httpok
   crashmail
   memmon

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

