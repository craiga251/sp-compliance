# SP Compliance Portal - Container Image
# Base image: Python 3.11 slim for small image size
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements first — Docker caches this layer
# Only rebuilds if requirements.txt changes
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY engine/ ./engine/
COPY .streamlit/ ./.streamlit/

# Streamlit configuration
ENV STREAMLIT_SERVER_PORT=8080
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_HEADLESS=true

# Cloud Run expects port 8080
EXPOSE 8080

# Run the portal
CMD ["streamlit", "run", "app.py"]