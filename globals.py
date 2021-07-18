import threading

# These are here to handle input passing between threads.
cmd_sema = threading.Semaphore(0)
chat_input = ""
