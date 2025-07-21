#!/bin/bash

# API Workshop Setup Script

echo "Setting up API Workshop environment..."

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Run the application
echo "Starting the API server..."
echo "The API will be available at: http://localhost:5000"
echo "Swagger documentation at: http://localhost:5000/hidden/swagger"
echo ""
echo "To add a user, use:"
echo "curl -X POST http://localhost:5000/admin/add_user \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -H \"X-Admin-Password: workshop_admin_pass\" \\"
echo "  -d '{\"email\": \"user@example.com\"}'"
echo ""

python app.py
