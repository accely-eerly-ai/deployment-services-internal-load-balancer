#!/bin/bash

# Default port
PORT=${1:-8000}

# Default workers (optional argument)
WORKERS=${2}

# Helper function to kill processes by port and ensure child processes are killed as well
kill_process_by_port() {
  PORT=$1
  # Get the PIDs of processes listening on the given port
  PIDS=$(lsof -t -i:$PORT)
  
  if [ -n "$PIDS" ]; then
    echo "Killing processes on port $PORT with PIDs: $PIDS"
    kill -9 $PIDS
    echo "Processes on port $PORT terminated."
  else
    echo "No process found on port $PORT."
  fi
}

# Step 1: Kill any processes on the specified port
kill_process_by_port $PORT

# Step 2: Pull the latest code from the main branch
git pull origin main

# Step 3: Check if the virtual environment exists, create it if not
if [ ! -d "venv" ]; then
  echo "Virtual environment not found, creating it..."
  python3 -m venv venv
else
  echo "Virtual environment already exists."
fi

# Step 4: Activate the virtual environment
source venv/bin/activate

# Step 5: Install required dependencies
echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# Step 6: Prepare the uvicorn command
UVICORN_CMD="uvicorn app.main:app --host 0.0.0.0 --port $PORT"

# If WORKERS is provided, add it to the uvicorn command
if [ -n "$WORKERS" ]; then
  UVICORN_CMD="$UVICORN_CMD --workers $WORKERS"
  echo "Starting application with $WORKERS workers..."
else
  echo "Starting application with default worker configuration..."
fi

# Step 7: Run the application
nohup $UVICORN_CMD &

# Step 8: Deactivate the virtual environment
deactivate
