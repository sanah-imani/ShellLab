<h> Shell Lab</h>

A shell is an interactive command-line interpreter that runs programs on behalf of the user. A shell repeatedly prints a prompt, waits for a command line on stdin, and then carries out some action, as directed by the contents of the command line.

Each command consists of one or more words, the first of which is the name of an action to perform. This may either be the path to an executable file (e.g., tsh> /bin/ls), or a builtin command—a word with special meaning to the shell—(e.g., tsh> quit). Following this are command-line arguments to be passed to the command. 

The child processes created as a result of interpreting a single command line are known collectively as a job. We just saw one type of job, a foreground job. However, sometimes a user wants to do more than one thing at once: in this case, they can instruct the shell not to wait for a command to terminate by instead running it as a background job. 

Three signal handlers were implemented here:
<ul>
  <li> sigchld handler: Handles SIGCHLD signals. </li>
  <li> sigint handler: Handles SIGINT signals (sent by Ctrl-C). </li>
  <li> sigtstp handler: Handles SIGTSTP signals (sent by Ctrl-Z). </li>
 </ul>
