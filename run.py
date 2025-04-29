import subprocess
import time
import sys
import os

def run_flask_app():
    while True:
        print("\nStarting Flask application...")
        try:
            # Activate virtual environment and run the Flask app
            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    [
                        'cmd', '/c',
                        '.\\venv\\Scripts\\activate && python app.py'
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
            else:  # Unix/Linux/Mac
                process = subprocess.Popen(
                    [
                        '/bin/bash', '-c',
                        'source ./venv/bin/activate && python app.py'
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )

            # Print output in real-time
            while True:
                output = process.stdout.readline()
                if output:
                    print(output.strip())
                if process.poll() is not None:
                    break

            # If we get here, the process has ended
            print("\nFlask application stopped. Restarting in 5 seconds...")
            time.sleep(5)

        except KeyboardInterrupt:
            print("\nShutting down the application...")
            if process:
                process.terminate()
            sys.exit(0)
        except Exception as e:
            print(f"\nError: {e}")
            print("Restarting in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    run_flask_app() 