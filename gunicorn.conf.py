import multiprocessing
import os 


# Gunicorn configuration
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
workers = 4
worker_class = "gthread"
threads = 2
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
worker_tmp_dir = "/dev/shm"  # Use shared memory for temp files

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# SSL (if needed)
# keyfile = "path/to/keyfile"
# certfile = "path/to/certfile"

# Process naming
proc_name = "studentease" 


