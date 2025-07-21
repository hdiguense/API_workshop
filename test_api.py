#!/usr/bin/env python3
"""
Test script for API Workshop
This script tests all endpoints to ensure they work correctly
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"
ADMIN_PASSWORD = "workshop_admin_pass"
TEST_EMAIL = "test@workshop.com"

def test_add_user():
    """Test adding a user"""
    print("=== Testing Add User ===")
    response = requests.post(
        f"{BASE_URL}/admin/add_user",
        headers={
            "Content-Type": "application/json",
            "X-Admin-Password": ADMIN_PASSWORD
        },
        json={"email": TEST_EMAIL}
    )
    
    if response.status_code == 201:
        data = response.json()
        print(f"✅ User created successfully!")
        print(f"Email: {data['email']}")
        print(f"API Key: {data['api_key']}")
        return data['api_key']
    else:
        print(f"❌ Failed to create user: {response.text}")
        return None

def test_get_token(api_key):
    """Test getting authentication token"""
    print("\n=== Testing Get Token ===")
    response = requests.post(
        f"{BASE_URL}/api/auth/token",
        headers={"Content-Type": "application/json"},
        json={"api_key": api_key}
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Token generated successfully!")
        print(f"Token expires at: {data['expires_at']}")
        return data['token']
    else:
        print(f"❌ Failed to get token: {response.text}")
        return None

def test_task1(token):
    """Test Task 1 - GET request"""
    print("\n=== Testing Task 1 (GET) ===")
    response = requests.get(
        f"{BASE_URL}/api/task1",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Task 1 completed successfully!")
        print(f"Task ID: {data['task_id']}")
        print(f"Next endpoint: {data['next_endpoint']}")
        return data['task_id']
    else:
        print(f"❌ Task 1 failed: {response.text}")
        return None

def test_task2(token, task_id):
    """Test Task 2 - POST request"""
    print("\n=== Testing Task 2 (POST) ===")
    response = requests.post(
        f"{BASE_URL}/api/task2",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        json={"task_id": task_id}
    )
    
    if response.status_code == 201:
        data = response.json()
        print(f"✅ Task 2 completed successfully!")
        print(f"Task Record ID: {data['task_record_id']}")
        print(f"Next endpoint: {data['next_endpoint']}")
        return data['task_record_id']
    else:
        print(f"❌ Task 2 failed: {response.text}")
        return None

def test_task3(token, task_record_id):
    """Test Task 3 - PUT request"""
    print("\n=== Testing Task 3 (PUT) ===")
    response = requests.put(
        f"{BASE_URL}/api/task3/{task_record_id}",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        json={"data": "Test data for task 3 update"}
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Task 3 completed successfully!")
        print(f"Action ID: {data['action_id']}")
        print(f"Next endpoint: {data['next_endpoint']}")
        return data['action_id']
    else:
        print(f"❌ Task 3 failed: {response.text}")
        return None

def test_task4(token, action_id):
    """Test Task 4 - DELETE request"""
    print("\n=== Testing Task 4 (DELETE) ===")
    response = requests.delete(
        f"{BASE_URL}/api/task4",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        json={"action_id": action_id}
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Task 4 completed successfully!")
        print(f"Certification ID: {data['certification_id']}")
        print(f"Message: {data['message']}")
        return True
    else:
        print(f"❌ Task 4 failed: {response.text}")
        return False

def test_home_endpoint():
    """Test home endpoint"""
    print("\n=== Testing Home Endpoint ===")
    response = requests.get(f"{BASE_URL}/")
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Home endpoint working!")
        print(f"Message: {data['message']}")
        return True
    else:
        print(f"❌ Home endpoint failed: {response.text}")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting API Workshop Tests")
    print("Make sure the API server is running at http://localhost:5000")
    
    # Wait for user confirmation
    input("Press Enter to continue...")
    
    # Test home endpoint
    if not test_home_endpoint():
        print("❌ Home endpoint test failed. Is the server running?")
        return
    
    # Test adding user
    api_key = test_add_user()
    if not api_key:
        return
    
    # Test getting token
    token = test_get_token(api_key)
    if not token:
        return
    
    # Test Task 1
    task_id = test_task1(token)
    if not task_id:
        return
    
    # Test Task 2
    task_record_id = test_task2(token, task_id)
    if not task_record_id:
        return
    
    # Test Task 3
    action_id = test_task3(token, task_record_id)
    if not action_id:
        return
    
    # Test Task 4
    if test_task4(token, action_id):
        print("\n🎉 All tests completed successfully!")
        print("The API Workshop is ready for use!")
    else:
        print("\n❌ Some tests failed")

if __name__ == "__main__":
    main()
