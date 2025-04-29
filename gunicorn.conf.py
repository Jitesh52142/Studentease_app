import multiprocessing

# Gunicorn configuration
bind = "0.0.0.0:10000"
workers = multiprocessing.cpu_count() * 2 + 1
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